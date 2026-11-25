"""Calibration, decision policy, triage priority, temporal correlation and drift (PSI)."""
import math

import numpy as np
import pandas as pd

from .data import BENIGN

NORMAL, KNOWN, UNKNOWN = "NORMAL", "KNOWN_ATTACK", "UNKNOWN_ANOMALY"
UNCERTAIN, DEGRADED, ERROR = "UNCERTAIN_REVIEW", "DEGRADED_REVIEW", "PROCESSING_ERROR"
VERDICTS = [NORMAL, KNOWN, UNKNOWN, UNCERTAIN, DEGRADED, ERROR]


# ---------- finite-sample calibration ----------

def order_statistic(scores, level):
    """k-th smallest score with k = ceil((n+1)*level). Returns (value or None when k > n, k, n)."""
    s = np.sort(np.asarray(scores, dtype=float))
    n = len(s)
    k = math.ceil(round((n + 1) * level, 9))  # round() stops float noise turning 99.0000001 into 100
    return (float(s[k - 1]) if 1 <= k <= n else None), k, n


def anomaly_threshold(benign_scores, beta):
    """Benign FPR threshold from anom_cal. Flag only when score > threshold (ties are not flagged)."""
    thr, k, n = order_statistic(benign_scores, 1 - beta)
    s = np.sort(np.asarray(benign_scores, dtype=float))
    return {"threshold": thr, "threshold_mode": "finite" if thr is not None else "no_trigger",
            "target_fpr": beta, "n": n, "k": k,
            "rule": "flag if score > k-th smallest of n benign anom_cal scores, k = ceil((n+1)(1-beta)); "
                    "k > n -> no_trigger (threshold = +inf)",
            "calibration_exceedances": int((s > thr).sum()) if thr is not None else 0,
            "reference_scores": s.tolist()}


def novelty_triggered(scores, cal):
    thr = cal["threshold"]
    return np.zeros(len(scores), bool) if thr is None else np.asarray(scores) > thr


def ecdf(reference_sorted, x):
    """Fraction of benign anom_cal scores <= x (ties count as <=), in [0, 1]."""
    ref = np.asarray(reference_sorted)
    return np.searchsorted(ref, np.asarray(x, dtype=float), side="right") / len(ref)


def conformal_quantiles(proba, y_true, classes, alpha):
    out = {}
    for j, c in enumerate(classes):
        q, k, n = order_statistic(1 - proba[np.asarray(y_true) == c, j], 1 - alpha)
        out[c] = {"q": 1.0 if q is None else q, "n": n, "k": k, "insufficient_calibration_support": q is None}
    return out


def conformal_sets(proba, classes, quantiles):
    q = np.array([quantiles[c]["q"] for c in classes])
    keep = (1 - proba) <= q
    return [[c for c, m in zip(classes, row) if m] for row in keep]


# ---------- decision policy (architecture.md 6.4 is authoritative) ----------

def decide(novelty, cset, error=None):
    """Returns (verdict, novelty_conflict). novelty/cset None = that model was unavailable."""
    if error:
        return ERROR, False
    if novelty is None or cset is None:
        return DEGRADED, False  # one model alone can never declare NORMAL
    if len(cset) == 1 and cset[0] != BENIGN:
        return KNOWN, bool(novelty)
    if cset == [BENIGN]:
        return (UNKNOWN if novelty else NORMAL), False
    return (UNKNOWN if novelty else UNCERTAIN), False


# ---------- triage priority (heuristic, never a verdict input) ----------

# Provisional placeholder weights from the design docs; not tuned.
PRIORITY_WEIGHTS = {"cls": .45, "anom": .30, "entropy": .10, "burst": .15}


def normalized_entropy(proba):
    p = np.clip(proba, 1e-12, 1)
    return (-(p * np.log(p)).sum(axis=1) / math.log(proba.shape[1])) if proba.shape[1] > 1 else np.zeros(len(p))


def priority(components):
    """components: name -> array in [0,1] or None (unavailable). Missing components are dropped and the
    remaining weights renormalised (policy 'priority-v1-renormalized'); they are never replaced by zero."""
    avail = {k: np.asarray(v, float) for k, v in components.items() if v is not None}
    if not avail:
        return None, sorted(components)
    wsum = sum(PRIORITY_WEIGHTS[k] for k in avail)
    score = 100 * np.clip(sum(PRIORITY_WEIGHTS[k] * v for k, v in avail.items()) / wsum, 0, 1)
    return score, sorted(set(components) - set(avail))


def priority_band(score, cutoffs):
    """Operational display band from validation-score quantile cutoffs; not ground-truth severity."""
    if score is None or not np.isfinite(score):
        return None
    return ["LOW", "MEDIUM", "HIGH", "CRITICAL"][int(np.searchsorted(cutoffs, score, side="right"))]


# ---------- temporal correlation ----------

def correlate(verdict, meta, window="30s", min_flows=3, burst_cap=10):
    """Group suspicious flows per (session, source host) within a rolling event-time window.

    Returns (burst, incident_id, enabled). Never removes or changes a row; rows without usable
    timestamp/host get burst NaN. Late/out-of-order records are handled by sorting the whole batch.
    """
    burst = pd.Series(np.nan, index=verdict.index)
    incident = pd.Series(None, index=verdict.index, dtype=object)
    if meta is None or not {"timestamp", "source_ip"} <= set(meta.columns):
        return burst, incident, False
    ok = meta["timestamp"].notna() & meta["source_ip"].notna()
    if not ok.any():
        return burst, incident, False
    burst[ok] = 0.0
    sus = pd.DataFrame({"ts": meta["timestamp"], "src": meta["source_ip"].astype(str),
                        "sess": meta.get("session", pd.Series("run", index=meta.index)).astype(str)})
    sus = sus[ok & verdict.ne(NORMAL)].sort_values(["sess", "src", "ts"], kind="stable")
    if sus.empty:
        return burst, incident, True
    counts = (sus.assign(one=1.0).set_index("ts").groupby(["sess", "src"], sort=True)["one"]
              .rolling(window).count().to_numpy())
    burst[sus.index] = np.minimum(counts / burst_cap, 1.0)
    new_host = (sus["sess"] != sus["sess"].shift()) | (sus["src"] != sus["src"].shift())
    chain = (new_host | (sus["ts"].diff() > pd.Timedelta(window))).cumsum()
    size = chain.map(chain.value_counts())
    start = sus.groupby(chain)["ts"].transform("min")
    big = size >= min_flows
    incident[sus.index[big]] = (sus["sess"] + "|" + sus["src"] + "|" + start.astype(str))[big].to_numpy()
    return burst, incident, True


# ---------- drift ----------

PSI_EPS, PSI_MIN_BATCH = 1e-4, 500


def psi_baseline(X, features, bins=10):
    base = {}
    for c in features:
        x = X[c].to_numpy(float)
        edges = np.unique(np.nanquantile(x, np.linspace(0, 1, bins + 1)[1:-1])) if np.isfinite(x).any() else np.array([])
        base[c] = {"edges": edges.tolist(), "props": _bin_props(x, edges).tolist()}
    return base


def _bin_props(x, edges):
    idx = np.where(np.isnan(x), len(edges) + 1, np.searchsorted(edges, x, side="right"))  # last bin = missing
    counts = np.bincount(idx, minlength=len(edges) + 2).astype(float)
    return counts / max(len(x), 1)


def psi(baseline, X):
    """Per-feature PSI on a replay batch. A warning signal only: never changes verdicts or retrains."""
    if len(X) < PSI_MIN_BATCH:
        return {"status": "insufficient_batch", "batch_size": len(X), "min_batch": PSI_MIN_BATCH, "features": {}}
    out = {}
    for c, b in baseline.items():
        p = np.asarray(b["props"]) + PSI_EPS
        q = _bin_props(X[c].to_numpy(float), np.asarray(b["edges"])) + PSI_EPS
        p, q = p / p.sum(), q / q.sum()
        out[c] = float(((p - q) * np.log(p / q)).sum())
    worst = max(out.values()) if out else 0.0
    status = "stable" if worst < .10 else "moderate_shift" if worst < .25 else "significant_shift"
    return {"status": status, "max_psi": worst, "batch_size": len(X), "epsilon": PSI_EPS,
            "missing_rate": float(X[list(baseline)].isna().mean().mean()), "features": out}
