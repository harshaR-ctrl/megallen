"""Checklist tests from architecture.md section 14, pipeline.md section 16 and workflow.md section 5."""
import json
import shutil

import numpy as np
import pandas as pd
import pytest

import run
from ids import core, data, pipeline
from ids.core import DEGRADED, ERROR, KNOWN, NORMAL, UNCERTAIN, UNKNOWN, decide


# ---------- synthetic CIC-shaped fixture ----------

def write_cic(dirpath, seed=0):
    rng = np.random.default_rng(seed)
    centers = {"BENIGN": 0, "DoS Hulk": 6, "PortScan": -6, "Bot": 12, "Web Attack \x96 XSS": 18}
    sizes = {"BENIGN": 3000, "DoS Hulk": 600, "PortScan": 400, "Bot": 400, "Web Attack \x96 XSS": 30}
    dirpath.mkdir(parents=True, exist_ok=True)
    for day, labels in enumerate([["BENIGN", "DoS Hulk", "Bot"], ["BENIGN", "PortScan", "Web Attack \x96 XSS"]]):
        rows = []
        for lab in labels:
            n = sizes[lab] // (2 if lab == "BENIGN" else 1)
            feats = rng.normal(centers[lab], 1, size=(n, 4))
            t0 = pd.Timestamp(f"2017-07-0{day + 3} 09:00:00")
            for i in range(n):
                rows.append({"Flow ID": f"f{day}-{lab}-{i}", " Source IP": f"10.0.{day}.{i % 7}",
                             " Source Port": 40000 + i, " Destination IP": "192.168.0.1",
                             " Destination Port": 80 if lab != "PortScan" else int(rng.integers(1, 1024)),
                             " Timestamp": (t0 + pd.Timedelta(seconds=i)).strftime("%d/%m/%Y %H:%M:%S"),
                             " Flow Duration": feats[i, 0], " Total Fwd Packets": feats[i, 1],
                             "Flow Bytes/s": feats[i, 2] if i % 50 else np.inf, " Flow IAT Mean": feats[i, 3],
                             " Label": lab})
        pd.DataFrame(rows).to_csv(dirpath / f"day{day}.csv", index=False)
    pd.DataFrame([{"Flow ID": "x", " Label": "BENIGN", "other": 1}]).to_csv(dirpath / "zz_bad_schema.csv", index=False)
    return dirpath


@pytest.fixture(scope="module")
def cic(tmp_path_factory):
    raw = write_cic(tmp_path_factory.mktemp("cic"))
    hashes = {p.name: data.sha256(p) for p in raw.iterdir()}
    df, info, report = data.load_cic(raw)
    return raw, hashes, df, info, report


@pytest.fixture(scope="module")
def trained(cic):
    _, _, df, info, _ = cic
    part = data.make_split(df, "PortScan", seed=1)
    return df, info, part, pipeline.train(df, part, info, "PortScan", seed=1, n_estimators=50)


# ---------- data and leakage ----------

def test_loader_keeps_raw_files_unchanged_and_quarantines_bad_schema(cic):
    raw, hashes, _, _, report = cic
    assert {p.name: data.sha256(p) for p in raw.iterdir()} == hashes
    assert [q["file"] for q in report["quarantined_files"]] == ["zz_bad_schema.csv"]
    assert report["infinite_values"]["flow_bytes_s"] > 0


def test_features_exclude_identifiers_and_labels(cic):
    _, _, df, info, _ = cic
    forbidden = set(data.INTERNAL) | set(data.CIC_METADATA) | {"label"}
    assert not forbidden & set(info["features"])
    assert "destination_port" in info["features"]  # ablated only via --no-port


def test_label_mapping_never_maps_unknown_to_benign():
    assert data.CIC_FAMILY.get("brand new attack") is None
    assert data.NSL_FAMILY.get("brand_new_attack") is None
    df = pd.DataFrame({"a": [1.0, 2.0, 3.0], "label_raw": ["normal", "weird", "neptune"], "source_file": "f",
                       "session": None})
    df["label"] = df["label_raw"].map(data.NSL_FAMILY).fillna(data.UNMAPPED)
    out, _, report = data.finish(df, "t", ["a"], [], [], [], [])
    assert list(out["label"]) == ["BENIGN", "DoS"] and report["unmapped_labels"] == {"weird": 1}


def test_conflicting_labels_are_quarantined():
    df = pd.DataFrame({"a": [1.0, 1.0, 2.0], "label_raw": ["x", "y", "x"], "label": ["BENIGN", "DoS", "BENIGN"],
                       "source_file": "f", "session": None})
    out, _, report = data.finish(df, "t", ["a"], [], [], [], [])
    assert len(out) == 1 and report["conflicting_label_rows"] == 2


def test_split_is_disjoint_grouped_and_holds_out_family(trained):
    df, _, part, _ = trained
    audit = data.audit_split(df, part, "PortScan", data.rare_families(df, "PortScan", .05))
    assert all(v for k, v in audit["checks"].items() if k != "anom_cal_conf_cal_row_overlap")
    assert set(df.loc[part == "anom_cal", "label"]) == {"BENIGN"}
    assert set(df.loc[df["label"] == "PortScan"].index) <= set(part.index[part == "test"])
    assert not any(audit["feature_vector_overlap"].values())  # identical vectors never cross partitions
    assert "WebAttack" in audit["rare_families_excluded_from_known_set"]  # 30 rows cannot be calibrated


def test_small_class_gets_enough_conformal_calibration_rows():
    df = pd.DataFrame({"label": ["BENIGN"] * 500 + ["U2R"] * 70, "fingerprint": np.arange(570)})
    part = data.make_split(df, "nothing", seed=0)
    assert (part[df["label"] == "U2R"] == "conf_cal").sum() >= data.min_calibration_rows(.05)


# ---------- calibration ----------

def test_finite_sample_threshold_and_no_trigger_fallback():
    cal = core.anomaly_threshold(np.arange(1, 100), beta=0.01)  # n=99 -> k=ceil(100*.99)=99 -> max
    assert (cal["k"], cal["threshold"]) == (99, 99.0)
    assert list(core.novelty_triggered(np.array([99.0, 99.5]), cal)) == [False, True]  # strict >
    small = core.anomaly_threshold(np.arange(50), beta=0.01)  # k=ceil(51*.99)=51 > 50
    assert small["threshold"] is None and small["threshold_mode"] == "no_trigger"
    assert not core.novelty_triggered(np.array([1e9]), small).any()
    json.dumps(small, allow_nan=False)


def test_conformal_quantiles_and_fallback():
    proba = np.array([[.9, .1]] * 19 + [[.2, .8]] * 3)
    y = ["A"] * 19 + ["B"] * 3
    q = core.conformal_quantiles(proba, y, ["A", "B"], alpha=.05)
    assert q["A"]["k"] == 19 and q["A"]["q"] == pytest.approx(.1)
    assert q["B"]["insufficient_calibration_support"] and q["B"]["q"] == 1.0
    assert core.conformal_sets(np.array([[.9, .1], [.85, .15]]), ["A", "B"], q) == [["A", "B"], ["B"]]


def test_anomaly_score_direction(trained):
    df, info, part, bundle = trained
    ben = df.loc[(part == "test") & (df["label"] == "BENIGN"), info["features"]].head(200)
    far = ben.copy()
    far[info["numeric"]] = 1e6
    assert np.median(pipeline.anomaly_scores(bundle, far)) > np.median(pipeline.anomaly_scores(bundle, ben))


# ---------- decision policy ----------

@pytest.mark.parametrize("novelty,cset,error,expected", [
    (False, ["DoS"], None, (KNOWN, False)),
    (True, ["DoS"], None, (KNOWN, True)),
    (False, ["BENIGN"], None, (NORMAL, False)),
    (True, ["BENIGN"], None, (UNKNOWN, False)),
    (True, [], None, (UNKNOWN, False)),
    (True, ["BENIGN", "DoS"], None, (UNKNOWN, False)),
    (False, [], None, (UNCERTAIN, False)),
    (False, ["BENIGN", "DoS"], None, (UNCERTAIN, False)),
    (None, ["BENIGN"], None, (DEGRADED, False)),   # novelty model unavailable
    (False, None, None, (DEGRADED, False)),        # classifier unavailable
    (False, ["BENIGN"], "schema mismatch", (ERROR, False)),
])
def test_decision_table(novelty, cset, error, expected):
    assert decide(novelty, cset, error) == expected


def test_failures_never_produce_normal(trained):
    df, info, part, bundle = trained
    X = df.loc[part == "test", info["features"]].head(100)
    assert set(pipeline.infer(bundle, X[X.columns[::-1]])["verdict"]) == {ERROR}  # reordered columns
    assert set(pipeline.infer(bundle, X.drop(columns=X.columns[0]))["verdict"]) == {ERROR}  # missing feature
    bad = X.astype({X.columns[0]: str})
    assert set(pipeline.infer(bundle, bad)["verdict"]) == {ERROR}  # incompatible dtype
    assert set(pipeline.infer(dict(bundle, supervised_model=None), X)["verdict"]) == {DEGRADED}
    assert set(pipeline.infer(dict(bundle, isolation_forest=None), X)["verdict"]) == {DEGRADED}


def test_end_to_end_inference_contract(trained):
    df, info, part, bundle = trained
    test = df[part == "test"]
    res = pipeline.infer(bundle, test[info["features"]], test[info["metadata"] + ["session"]])
    assert len(res) == len(test) and NORMAL in set(res["verdict"])
    conflict = res[res["novelty_conflict"]]
    assert (conflict["verdict"] == KNOWN).all() and conflict["analyst_review_required"].all()
    rec = pipeline.to_contract(bundle, res.iloc[0], test.iloc[0], "exp", "replay-0")
    json.dumps(rec, allow_nan=False)
    assert list(rec["signals"]["classifier_scores"]) == bundle["feature_schema"]["classes"]
    assert "label" not in json.dumps(rec["metadata"])
    exp = pipeline.explain(bundle, test[info["features"]].iloc[[0]], res.iloc[0])
    assert exp["shap"]["method"].startswith("TreeSHAP") and "not SHAP" in exp["baseline_deviation"][0]["method"]


# ---------- correlation, priority, drift ----------

def test_correlation_groups_without_dropping_and_disables_without_metadata():
    ts = pd.Timestamp("2017-07-03 09:00")
    meta = pd.DataFrame({"timestamp": [ts + pd.Timedelta(seconds=s) for s in [0, 5, 10, 200, 0]],
                         "source_ip": ["a", "a", "a", "a", "b"], "session": "d1"})
    verdict = pd.Series([UNKNOWN, KNOWN, UNCERTAIN, UNKNOWN, NORMAL])
    burst, incident, enabled = core.correlate(verdict, meta)
    assert enabled and len(burst) == 5
    assert incident[:3].nunique() == 1 and incident[3:].isna().all()
    assert burst[2] == pytest.approx(.3) and burst[4] == 0
    _, _, enabled = core.correlate(verdict, pd.DataFrame({"x": range(5)}))
    assert not enabled


def test_priority_is_bounded_partial_and_independent_of_verdict():
    score, missing = core.priority({"cls": [1, 0], "anom": [1, 0], "entropy": [0, 0], "burst": None})
    assert missing == ["burst"] and score[0] <= 100 and score[1] == 0
    assert core.priority_band(50, [10, 60, 90]) == "MEDIUM"


def test_psi_stable_shifted_and_small_batch():
    rng = np.random.default_rng(0)
    base = pd.DataFrame({"x": rng.normal(size=5000)})
    b = core.psi_baseline(base, ["x"])
    assert core.psi(b, pd.DataFrame({"x": rng.normal(size=2000)}))["status"] == "stable"
    assert core.psi(b, pd.DataFrame({"x": rng.normal(3, 1, size=2000)}))["status"] == "significant_shift"
    assert core.psi(b, base.head(10))["status"] == "insufficient_batch"


# ---------- bundle ----------

def test_run_writes_verified_bundle_and_rejects_tampering(cic, tmp_path):
    raw = cic[0]
    run.main(["cic_ids2017", "--holdout", "PortScan", "--raw-dir", str(raw), "--trees", "30"])
    path = pipeline.ARTIFACTS / "cic_ids2017" / "lofo-portscan-grouped"
    try:
        b = pipeline.load_bundle(path)
        m = b["metrics"]["test"]
        assert m["lofo"]["n"] > 0 and "WebAttack" in m["rare_families_excluded_from_known_set"]
        assert b["calibration"]["anomaly"]["threshold_mode"] in {"finite", "no_trigger"}
        (path / "metrics.json").write_text("{}")
        with pytest.raises(ValueError, match="checksum"):
            pipeline.load_bundle(path)
        with pytest.raises(PermissionError):
            pipeline.load_bundle(tmp_path)
    finally:
        shutil.rmtree(path, ignore_errors=True)
