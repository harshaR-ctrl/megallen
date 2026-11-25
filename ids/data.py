"""Dataset adapters, cleaning, leakage audit and split manifests.

CIC-IDS2017 and NSL-KDD have separate loaders and are never concatenated.
"""
import hashlib
import math
import re
from pathlib import Path

import numpy as np
import pandas as pd

BENIGN = "BENIGN"
UNMAPPED = "UNMAPPED"

NSL_COLUMNS = (
    "duration protocol_type service flag src_bytes dst_bytes land wrong_fragment urgent hot "
    "num_failed_logins logged_in num_compromised root_shell su_attempted num_root num_file_creations "
    "num_shells num_access_files num_outbound_cmds is_host_login is_guest_login count srv_count "
    "serror_rate srv_serror_rate rerror_rate srv_rerror_rate same_srv_rate diff_srv_rate "
    "srv_diff_host_rate dst_host_count dst_host_srv_count dst_host_same_srv_rate "
    "dst_host_diff_srv_rate dst_host_same_src_port_rate dst_host_srv_diff_host_rate "
    "dst_host_serror_rate dst_host_srv_serror_rate dst_host_rerror_rate dst_host_srv_rerror_rate "
    "label_raw difficulty"
).split()
NSL_CATEGORICAL = ["protocol_type", "service", "flag"]
# Standard NSL-KDD attack-name -> family mapping (Tavallaee et al. 2009 / KDD'99 taxonomy).
NSL_FAMILY = {"normal": BENIGN} | {
    name: fam
    for fam, names in {
        "DoS": "back land neptune pod smurf teardrop apache2 udpstorm processtable mailbomb",
        "Probe": "satan ipsweep nmap portsweep mscan saint",
        "R2L": "guess_passwd ftp_write imap phf multihop warezmaster warezclient spy xlock xsnoop "
        "snmpguess snmpgetattack httptunnel sendmail named worm",
        "U2R": "buffer_overflow loadmodule rootkit perl sqlattack xterm ps",
    }.items()
    for name in names.split()
}

# CIC-IDS2017 label -> family; keys are labels lower-cased with non-alphanumerics collapsed to spaces
# (this also absorbs the mis-encoded dash in "Web Attack – Brute Force").
CIC_FAMILY = {
    "benign": BENIGN,
    "dos hulk": "DoS", "dos goldeneye": "DoS", "dos slowloris": "DoS", "dos slowhttptest": "DoS",
    "ddos": "DDoS",
    "portscan": "PortScan",
    "bot": "Bot",
    "ftp patator": "BruteForce", "ssh patator": "BruteForce",
    "web attack brute force": "WebAttack", "web attack xss": "WebAttack", "web attack sql injection": "WebAttack",
    "infiltration": "Infiltration",
    "heartbleed": "Heartbleed",
}
# Identifiers kept as metadata only. Destination Port stays a feature unless the no-port ablation drops it.
CIC_METADATA = ["flow_id", "source_ip", "source_port", "destination_ip", "timestamp"]
# Bookkeeping columns that must never reach a model.
INTERNAL = ["row_id", "label", "label_raw", "difficulty", "source_file", "source_row", "official_split",
            "fingerprint", "session"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def norm_name(name):
    return re.sub(r"[^0-9a-z]+", "_", str(name).strip().lower()).strip("_")


def load_nsl(raw_dir):
    frames, provenance = [], []
    for split, fname in [("official_train", "KDDTrain+.txt"), ("official_test", "KDDTest+.txt")]:
        path = Path(raw_dir) / fname
        df = pd.read_csv(path, header=None)
        if df.shape[1] != len(NSL_COLUMNS):
            raise ValueError(f"{fname}: expected {len(NSL_COLUMNS)} fields, found {df.shape[1]}")
        df.columns = NSL_COLUMNS
        df["source_file"], df["source_row"], df["official_split"] = fname, np.arange(len(df)), split
        provenance.append({"file": fname, "sha256": sha256(path), "rows": len(df)})
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df["label_raw"] = df["label_raw"].astype(str).str.strip()
    df["label"] = df["label_raw"].str.lower().map(NSL_FAMILY).fillna(UNMAPPED)
    df["session"] = None  # NSL-KDD has no capture-session, host or time metadata
    features = NSL_COLUMNS[:41]
    return finish(df, "nsl_kdd", features, NSL_CATEGORICAL, [], provenance, [])


def load_cic(raw_dir, max_rows_per_class=None, seed=0):
    frames, provenance, quarantined_files, ref_cols = [], [], [], None
    paths = sorted(Path(raw_dir).glob("*.csv"))
    if not paths:
        raise FileNotFoundError(f"no CIC-IDS2017 CSV files in {raw_dir}")
    for path in paths:
        df = pd.read_csv(path, encoding="latin-1", low_memory=False)
        df.columns = [norm_name(c) for c in df.columns]
        if "label" not in df.columns or df.columns.duplicated().any():
            quarantined_files.append({"file": path.name, "reason": "missing label or duplicate columns"})
            continue
        if ref_cols is None:
            ref_cols = list(df.columns)
        elif set(df.columns) != set(ref_cols):
            quarantined_files.append({"file": path.name, "reason": "schema differs from first file",
                                      "missing": sorted(set(ref_cols) - set(df.columns)),
                                      "extra": sorted(set(df.columns) - set(ref_cols))})
            continue
        df = df[ref_cols]
        df["source_file"], df["source_row"] = path.name, np.arange(len(df))
        provenance.append({"file": path.name, "sha256": sha256(path), "rows": len(df)})
        frames.append(df)
    if not frames:
        raise ValueError(f"every CIC file was quarantined: {quarantined_files}")
    df = pd.concat(frames, ignore_index=True).rename(columns={"label": "label_raw"})
    df["label_raw"] = df["label_raw"].astype("string").str.strip()
    key = df["label_raw"].str.lower().str.replace(r"[^a-z0-9]+", " ", regex=True).str.strip()
    df["label"] = key.map(CIC_FAMILY).fillna(UNMAPPED)
    df["session"] = df["source_file"]  # one CIC file = one capture day
    if "timestamp" in df.columns:
        # shortcut: CIC timestamp timezone is undocumented, so times stay naive local; some files have minute resolution.
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", dayfirst=True, format="mixed")
    if max_rows_per_class:  # deterministic development sample
        df = df.sample(frac=1, random_state=seed).groupby("label").head(max_rows_per_class).sort_index()
    metadata = [c for c in CIC_METADATA if c in df.columns]
    features = [c for c in df.columns if c not in metadata + INTERNAL]
    return finish(df, "cic_ids2017", features, [], metadata, provenance, quarantined_files)


def finish(df, dataset, features, categorical, metadata, provenance, quarantined_files):
    """Convert types, report data quality, quarantine bad labels/conflicts, fingerprint feature vectors."""
    df = df.reset_index(drop=True)
    df["row_id"] = np.arange(len(df))
    numeric = [c for c in features if c not in categorical]
    report = {"dataset": dataset, "provenance": provenance, "quarantined_files": quarantined_files,
              "rows_loaded": len(df)}

    failed, inf = {}, {}
    for c in numeric:
        before = df[c].notna()
        df[c] = pd.to_numeric(df[c], errors="coerce").astype(float)
        if n := int((before & df[c].isna()).sum()):
            failed[c] = n
        is_inf = np.isinf(df[c])
        if n := int(is_inf.sum()):
            inf[c] = n
            df.loc[is_inf, c] = np.nan  # imputed later inside the fitted pipeline, never zero-filled here
    for c in categorical:
        df[c] = df[c].astype("string").str.strip()
    report["numeric_conversion_failures"] = failed
    report["infinite_values"] = inf
    report["missing_values"] = {c: int(n) for c, n in df[features].isna().sum().items() if n}
    report["constant_columns"] = [c for c in features if df[c].nunique(dropna=False) <= 1]
    report["label_variants"] = {str(k): int(v) for k, v in df["label_raw"].value_counts(dropna=False).items()}

    bad_label = df["label"].eq(UNMAPPED) | df["label_raw"].isna()
    report["unmapped_labels"] = {str(k): int(v) for k, v in df.loc[bad_label, "label_raw"].value_counts(dropna=False).items()}

    df["fingerprint"] = pd.util.hash_pandas_object(df[features], index=False).to_numpy()
    report["exact_duplicate_rows"] = int(df.duplicated(features + ["label"]).sum())
    report["duplicate_feature_vectors"] = int(df.duplicated(["fingerprint"]).sum())
    labels_per_fp = df[~bad_label].groupby("fingerprint")["label"].nunique()
    conflict = df["fingerprint"].isin(labels_per_fp[labels_per_fp > 1].index) & ~bad_label
    report["conflicting_label_rows"] = int(conflict.sum())
    report["quarantined_rows"] = {"unmapped_or_missing_label": int(bad_label.sum()), "conflicting_labels": int(conflict.sum())}
    report["quarantined_row_ids_sample"] = df.loc[bad_label | conflict, "row_id"].head(1000).tolist()
    df = df[~(bad_label | conflict)].reset_index(drop=True)

    report["class_counts"] = {str(k): int(v) for k, v in df["label"].value_counts().items()}
    report["class_counts_per_file"] = {f: {str(k): int(v) for k, v in g.value_counts().items()}
                                       for f, g in df.groupby("source_file")["label"]}
    leaked = set(features) & set(INTERNAL + CIC_METADATA)
    assert not leaked, f"identifier/label columns in feature matrix: {leaked}"
    report["excluded_columns"] = sorted(set(df.columns) - set(features))
    info = {"dataset": dataset, "features": features, "numeric": numeric, "categorical": categorical,
            "metadata": metadata}
    return df, info, report


BENIGN_WEIGHTS = {"train": .6, "validation": .1, "anom_cal": .1, "conf_cal": .1, "test": .1}
ATTACK_WEIGHTS = {"train": .65, "validation": .12, "conf_cal": .12, "test": .11}


def min_calibration_rows(alpha):
    """Smallest class count n with ceil((n+1)(1-alpha)) <= n, i.e. a finite conformal quantile exists."""
    return math.ceil(round((1 - alpha) / alpha, 9))


def rare_families(df, holdout, alpha):
    """Attack families too small to give conf_cal a finite quantile while keeping training data.
    Their include-always fallback would sit in every conformal set and block every NORMAL verdict,
    so they leave the known label set and are evaluated in test as unseen families instead."""
    pool = df[df["official_split"].eq("official_train")] if "official_split" in df.columns else df
    counts = pool.loc[pool["label"].ne(BENIGN) & pool["label"].ne(holdout)].groupby("label")["fingerprint"].nunique()
    return sorted(counts[counts < 3 * min_calibration_rows(alpha)].index)


def make_split(df, holdout, seed, method="grouped", alpha=0.05):
    """Assign every row to train/validation/anom_cal/conf_cal/test (or unused_holdout).

    grouped: identical feature vectors (same fingerprint) always land in one partition.
    random:  row-random assignment, kept only as a leakage/optimism audit.
    NSL-KDD keeps its official test file as `test`; splits are drawn from the official training file.
    Held-out and rare families never reach train/validation/conf_cal.
    """
    rng = np.random.default_rng(seed)
    part = pd.Series("unassigned", index=df.index, dtype=object)
    official = "official_split" in df.columns
    excluded = df["label"].isin([holdout, *rare_families(df, holdout, alpha)])
    if official:
        part[df["official_split"].eq("official_test")] = "test"
        pool = df["official_split"].eq("official_train")
        part[pool & excluded] = "unused_holdout"
    else:
        pool = pd.Series(True, index=df.index)
        part[excluded] = "test"
    n_min = min_calibration_rows(alpha)
    for label, sub in df[pool & ~excluded].groupby("label"):
        weights = dict(BENIGN_WEIGHTS if label == BENIGN else ATTACK_WEIGHTS)
        if official:
            weights.pop("test")
        codes, uniq = pd.factorize(sub["fingerprint"] if method == "grouped" else sub.index)
        n = len(uniq)
        total = sum(weights.values())
        if weights["conf_cal"] / total * n < n_min:  # small class: guarantee a finite conformal quantile
            rest = total - weights["conf_cal"]
            weights = {k: (n_min / n if k == "conf_cal" else w / rest * (1 - n_min / n)) for k, w in weights.items()}
            total = 1.0
        cuts = np.round(np.cumsum([w / total for w in weights.values()]) * n).astype(int)
        slot = np.searchsorted(cuts, np.arange(n), side="right")  # exact, seeded proportions per class
        assign = np.empty(n, dtype=object)
        assign[rng.permutation(n)] = np.array(list(weights))[slot]
        part[sub.index] = assign[codes]
    return part


def audit_split(df, part, holdout, rare=()):
    fp = df["fingerprint"]
    names = ["train", "validation", "anom_cal", "conf_cal", "test"]
    sets = {n: set(fp[part == n]) for n in names}
    overlap = {f"{a}|{b}": len(sets[a] & sets[b]) for i, a in enumerate(names) for b in names[i + 1:]}
    comp = {n: {str(k): int(v) for k, v in df.loc[part == n, "label"].value_counts().items()} for n in names}
    files = {n: {str(k): int(v) for k, v in df.loc[part == n, "source_file"].value_counts().items()} for n in names}
    checks = {
        "holdout_absent_from_train_validation_conf_cal":
            bool(not df.loc[part.isin(["train", "validation", "conf_cal"]), "label"].isin([holdout, *rare]).any()),
        "anom_cal_benign_only": bool(df.loc[part == "anom_cal", "label"].eq(BENIGN).all()),
        "partitions_disjoint": True,  # one partition label per row by construction
        "anom_cal_conf_cal_row_overlap": 0,
    }
    return {"rare_families_excluded_from_known_set": list(rare), "feature_vector_overlap": overlap, "label_composition": comp, "source_file_composition": files,
            "checks": checks}


def split_manifest(df, part, method, seed, holdout, rare=()):
    keep = part != "unassigned"
    return {"method": method, "seed": seed, "holdout_family": holdout, "rare_families_excluded": list(rare),
            "group_policy": "feature-vector fingerprint" if method == "grouped" else "row-random (audit only)",
            "weights": {"benign": BENIGN_WEIGHTS, "attack": ATTACK_WEIGHTS},
            "row_id": df.loc[keep, "row_id"].tolist(), "partition": part[keep].tolist(),
            "group_id": [str(x) for x in df.loc[keep, "fingerprint"]], "label": df.loc[keep, "label"].tolist()}
