"""Training, versioned artifact bundles, schema-validated inference, explanations and evaluation."""
import json
import platform
import shutil
import subprocess
import time
import tracemalloc
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import balanced_accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.preprocessing import OrdinalEncoder

from . import core
from .data import BENIGN, sha256

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts"
BUNDLE_VERSION = "1.0.0"
JOBLIBS = ["classifier_preprocessor", "novelty_preprocessor", "supervised_model", "isolation_forest"]
JSONS = ["calibration", "feature_schema", "split_manifest", "metrics", "run_manifest"]


def make_preprocessor(numeric, categorical):
    # Unknown or missing categories map to an explicit -1 bucket instead of an ordinary category.
    return ColumnTransformer([
        ("num", SimpleImputer(strategy="median", keep_empty_features=True), numeric),
        ("cat", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1, encoded_missing_value=-1),
         categorical),
    ])


def anomaly_scores(bundle, X):
    # Application convention: higher = more anomalous (negated decision_function).
    return -bundle["isolation_forest"].decision_function(bundle["novelty_preprocessor"].transform(X))


def train(df, part, info, holdout, seed=42, alpha=0.05, beta=0.01, n_estimators=200):
    feats, num, cat = info["features"], info["numeric"], info["categorical"]
    tr = df[part == "train"]
    clf_pre = make_preprocessor(num, cat).fit(tr[feats])
    clf = RandomForestClassifier(n_estimators=n_estimators, class_weight="balanced_subsample", min_samples_leaf=2,
                                 n_jobs=-1, random_state=seed).fit(clf_pre.transform(tr[feats]), tr["label"])
    ben = tr[tr["label"] == BENIGN]
    nov_pre = make_preprocessor(num, cat).fit(ben[feats])
    iso = IsolationForest(n_estimators=n_estimators, random_state=seed, n_jobs=-1).fit(nov_pre.transform(ben[feats]))
    classes = [str(c) for c in clf.classes_]
    bundle = {"classifier_preprocessor": clf_pre, "supervised_model": clf,
              "novelty_preprocessor": nov_pre, "isolation_forest": iso}

    anom_cal = df[part == "anom_cal"]
    conf_cal = df[part == "conf_cal"]
    calibration = {
        "anomaly": core.anomaly_threshold(anomaly_scores(bundle, anom_cal[feats]), beta),
        "score_direction": "higher = more anomalous; score = -IsolationForest.decision_function",
        "conformal": {"alpha": alpha, "nonconformity": "1 - p(y|x)",
                      "quantile_rule": "k_c = ceil((n_c+1)(1-alpha)); k_c > n_c -> q_c = 1.0 (include always)",
                      "classes": core.conformal_quantiles(clf.predict_proba(clf_pre.transform(conf_cal[feats])),
                                                          conf_cal["label"], classes, alpha)},
    }
    importances = pd.Series(clf.feature_importances_, index=num + cat)
    monitored = importances[num].nlargest(10).index.tolist()
    ben_num = ben[num]
    schema = {
        "dataset": info["dataset"], "bundle_version": BUNDLE_VERSION, "features": feats,
        "dtypes": {c: "categorical" if c in cat else "numeric" for c in feats},
        "numeric": num, "categorical": cat, "metadata": info["metadata"], "classes": classes,
        "benign_label": BENIGN, "holdout_family": holdout,
        "benign_reference": {c: {"median": _f(ben_num[c].median()), "p05": _f(ben_num[c].quantile(.05)),
                                 "p95": _f(ben_num[c].quantile(.95))} for c in num},
        "psi_baseline": core.psi_baseline(tr, monitored),
        "priority_policy": {"version": "priority-v1", "weights": core.PRIORITY_WEIGHTS, "kind": "heuristic",
                            "note": "provisional placeholder weights; missing components renormalised"},
    }
    bundle.update(calibration=calibration, feature_schema=schema)
    return bundle


def _f(x):
    return float(x) if x is not None and np.isfinite(x) else None


def infer(bundle, X, meta=None):
    """Score a batch. Returns one row per input row; failures route to PROCESSING_ERROR/DEGRADED_REVIEW."""
    schema, cal = bundle["feature_schema"], bundle["calibration"]
    classes, n = schema["classes"], len(X)
    out = pd.DataFrame(index=X.index)
    error = None
    if list(X.columns) != schema["features"]:
        error = "schema mismatch: feature names/order differ from bundle"
    elif bad := [c for c in schema["numeric"] if not pd.api.types.is_numeric_dtype(X[c])]:
        error = f"non-numeric dtype for numeric features: {bad[:5]}"

    proba = scores = None
    row_err = pd.Series(error, index=X.index, dtype=object)
    if error is None:
        if bundle.get("supervised_model") is not None:
            try:
                if [str(c) for c in bundle["supervised_model"].classes_] != classes:
                    raise ValueError("class order differs from bundle schema")
                proba = bundle["supervised_model"].predict_proba(bundle["classifier_preprocessor"].transform(X))
                row_err[~np.isfinite(proba).all(axis=1)] = "non-finite classifier output"
            except Exception as e:  # noqa: BLE001 - any model failure becomes a review state, never NORMAL
                row_err[:] = f"classifier failure: {e}"
        if bundle.get("isolation_forest") is not None:
            try:
                scores = anomaly_scores(bundle, X)
                row_err[~np.isfinite(scores) & row_err.isna()] = "non-finite anomaly score"
            except Exception as e:  # noqa: BLE001
                row_err[:] = f"novelty failure: {e}"

    sets = core.conformal_sets(proba, classes, cal["conformal"]["classes"]) if proba is not None else [None] * n
    trig = core.novelty_triggered(scores, cal["anomaly"]) if scores is not None else [None] * n
    errs = [e if isinstance(e, str) else None for e in row_err]  # pandas turns empty slots into NaN, which is truthy
    decided = [core.decide(None if t is None else bool(t), s, e) for t, s, e in zip(trig, sets, errs)]
    out["verdict"] = [d[0] for d in decided]
    out["novelty_conflict"] = [d[1] for d in decided]
    out["analyst_review_required"] = out["verdict"] != core.NORMAL
    out["conformal_set"] = sets
    out["known_attack_candidate"] = [s[0] if v == core.KNOWN else None for (v, _), s in zip(decided, sets)]
    out["novelty_triggered"] = list(trig)
    out["anomaly_score"] = scores if scores is not None else np.nan
    out["error"] = errs
    if proba is not None:
        for j, c in enumerate(classes):
            out[f"p_{c}"] = proba[:, j]
        out["predicted_class"] = np.array(classes)[proba.argmax(axis=1)]
        out["entropy"] = core.normalized_entropy(proba)
        out["s_cls"] = 1 - proba[:, classes.index(BENIGN)] if BENIGN in classes else np.nan
    if scores is not None:
        out["s_anom"] = core.ecdf(cal["anomaly"]["reference_scores"], scores)
    return correlate_and_prioritize(bundle, out, meta)


def correlate_and_prioritize(bundle, out, meta):
    """Temporal grouping + heuristic triage priority. Re-run on the whole replayed set; never drops rows."""
    burst, incident, enabled = core.correlate(out["verdict"], meta)
    out["burst"], out["incident_id"] = burst, incident
    comps = {"cls": out.get("s_cls"), "anom": out.get("s_anom"), "entropy": out.get("entropy"),
             "burst": burst if enabled else None}
    score, missing = core.priority(comps)
    out["priority"] = score if score is not None else np.nan
    out.loc[out["error"].notna(), "priority"] = np.nan
    out["priority_partial"] = ",".join(missing)
    cut = bundle["feature_schema"].get("priority_band_cutoffs")
    out["priority_band"] = [core.priority_band(s, cut) for s in out["priority"]] if cut else None
    return out


def to_contract(bundle, row, meta_row=None, experiment_id="", flow_id="", explanation=None):
    """Inference output contract (pipeline.md section 15). Ground truth is never included."""
    schema, cal = bundle["feature_schema"], bundle["calibration"]
    num = lambda v: None if v is None or (isinstance(v, float) and not np.isfinite(v)) else float(v)  # noqa: E731
    meta_row = meta_row if meta_row is not None else {}
    return _json_clean({
        "flow_id": flow_id, "dataset": schema["dataset"], "experiment_id": experiment_id,
        "model_version": schema["bundle_version"],
        "verdict": {"traffic_class": row["verdict"], "known_attack_candidate": row["known_attack_candidate"],
                    "conformal_set": row["conformal_set"], "novelty_conflict": bool(row["novelty_conflict"]),
                    "analyst_review_required": bool(row["analyst_review_required"])},
        "priority": {"score": num(row["priority"]), "kind": "heuristic", "band": row.get("priority_band")},
        "signals": {"anomaly_score": num(row.get("anomaly_score")), "anomaly_threshold": cal["anomaly"]["threshold"],
                    "novelty_triggered": row["novelty_triggered"],
                    "classifier_scores": {c: num(row.get(f"p_{c}")) for c in schema["classes"]},
                    "predictive_entropy_normalized": num(row.get("entropy")),
                    "temporal_burst_score": num(row.get("burst"))},
        "explanation": explanation,
        "metadata": {k: (None if pd.isna(meta_row.get(k)) else str(meta_row.get(k)))
                     for k in ["source_ip", "destination_ip", "timestamp"] if k in meta_row},
        "status": {"schema_valid": row["error"] is None or "schema" not in str(row["error"]),
                   "models_valid": row["error"] is None and row["verdict"] != core.DEGRADED,
                   "error": row["error"], "partial_signals": [p for p in str(row["priority_partial"]).split(",") if p]},
    })


HINTS = {
    core.KNOWN: "Review the source host's recent connections and gateway/firewall logs for the candidate attack pattern.",
    core.UNKNOWN: "Unusual traffic versus the benign baseline - inspect the host and related flows; not a confirmed zero-day.",
    core.UNCERTAIN: "Classifier is ambiguous - compare with neighbouring flows before deciding.",
    core.DEGRADED: "A model signal was unavailable - check the pipeline status before trusting this record.",
    core.ERROR: "Input failed validation - check the record schema; no verdict was produced.",
    core.NORMAL: "No action suggested.",
}


def explain(bundle, X_row, result_row, top=5):
    """TreeSHAP for the candidate/predicted class plus benign-baseline deviations (labelled separately)."""
    schema = bundle["feature_schema"]
    t0 = time.perf_counter()
    out = {"defensive_action": HINTS.get(result_row["verdict"], ""), "shap": None, "baseline_deviation": []}
    cls = result_row.get("known_attack_candidate") or result_row.get("predicted_class")
    try:
        import shap
        explainer = bundle.setdefault("_shap", shap.TreeExplainer(bundle["supervised_model"]))
        Xt = bundle["classifier_preprocessor"].transform(X_row)
        sv = np.asarray(explainer.shap_values(Xt, check_additivity=False))
        k = schema["classes"].index(cls)
        names = schema["numeric"] + schema["categorical"]
        contrib = sv[0, :, k] if sv.ndim == 3 and sv.shape[1] == len(names) else sv[k, 0, :]
        assert contrib.shape == (len(names),), f"unexpected SHAP shape {sv.shape}"
        order = np.argsort(-np.abs(contrib))[:top]
        out["shap"] = {"method": "TreeSHAP (supervised Random Forest)", "explained_class": cls,
                       "top_features": [{"feature": names[i], "value": _val(X_row[names[i]].iloc[0]),
                                         "contribution": float(contrib[i]),
                                         "direction": f"towards {cls}" if contrib[i] > 0 else f"away from {cls}"}
                                        for i in order]}
    except Exception as e:  # noqa: BLE001 - SHAP is optional
        out["shap"] = {"method": "unavailable", "reason": str(e)}
    devs = []
    for c, ref in schema["benign_reference"].items():
        v = X_row[c].iloc[0]
        if pd.isna(v) or ref["median"] is None:
            continue
        spread = (ref["p95"] or 0) - (ref["p05"] or 0)
        devs.append((abs(v - ref["median"]) / (spread if spread > 0 else 1.0), c, v, ref))
    out["baseline_deviation"] = [
        {"method": "benign baseline deviation (not SHAP, not causal)", "feature": c, "value": float(v),
         "benign_median": ref["median"], "benign_p95": ref["p95"], "relative_deviation": float(d)}
        for d, c, v, ref in sorted(devs, reverse=True)[:top]]
    out["explanation_latency_ms"] = (time.perf_counter() - t0) * 1000
    return out


def _val(v):
    return None if pd.isna(v) else (float(v) if isinstance(v, (int, float, np.number)) else str(v))


# ---------- bundle persistence ----------

def _json_clean(o):
    if isinstance(o, dict):
        return {str(k): _json_clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, np.ndarray)):
        return [_json_clean(v) for v in o]
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (float, np.floating)):
        return float(o) if np.isfinite(o) else None
    if isinstance(o, np.bool_):
        return bool(o)
    return o


def save_bundle(out_dir, bundle, extra_files=None):
    """Atomic write: build in <dir>.tmp, checksum every file, then swap into place."""
    out_dir = Path(out_dir)
    tmp = out_dir.with_name(out_dir.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    for name in JOBLIBS:
        joblib.dump(bundle[name], tmp / f"{name}.joblib")
    for name, obj in (extra_files or {}).items():
        joblib.dump(obj, tmp / name)
    for name in JSONS:
        if name == "run_manifest":
            continue
        (tmp / f"{name}.json").write_text(json.dumps(_json_clean(bundle[name]), allow_nan=False))
    files = {p.name: sha256(p) for p in sorted(tmp.iterdir())}
    manifest = dict(bundle["run_manifest"], files=files)
    (tmp / "run_manifest.json").write_text(json.dumps(_json_clean(manifest), allow_nan=False, indent=1))
    shutil.rmtree(out_dir, ignore_errors=True)
    tmp.rename(out_dir)


def load_bundle(path):
    """Load only checksum-verified bundles from this project's artifacts/ directory (joblib can execute code)."""
    path = Path(path).resolve()
    if ARTIFACTS.resolve() not in path.parents:
        raise PermissionError(f"refusing to load artifacts outside {ARTIFACTS}")
    manifest = json.loads((path / "run_manifest.json").read_text())
    for name, digest in manifest["files"].items():
        if sha256(path / name) != digest:
            raise ValueError(f"checksum mismatch for {name}; bundle may be corrupt or tampered")
    bundle = {n: joblib.load(path / f"{n}.joblib") for n in JOBLIBS}
    bundle.update({n: json.loads((path / f"{n}.json").read_text()) for n in JSONS})
    if bundle["feature_schema"]["bundle_version"] != BUNDLE_VERSION:
        raise ValueError("incompatible bundle version")
    bundle["path"] = path
    return bundle


def run_manifest(info, report, args, dataset_files):
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip() or None
    except OSError:
        commit = None
    import shap
    return {"dataset": info["dataset"], "experiment_id": args["experiment_id"], "args": args,
            "dataset_files": dataset_files, "excluded_columns": report["excluded_columns"],
            "code_commit": commit, "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "versions": {"python": platform.python_version(), "sklearn": sklearn.__version__,
                         "pandas": pd.__version__, "numpy": np.__version__, "shap": shap.__version__},
            "hardware": {"machine": platform.machine(), "processor": platform.processor(), "system": platform.platform()}}


# ---------- evaluation ----------

def wilson(k, n, z=1.96):
    """95% Wilson interval. Assumes independent rows; session dependence makes it optimistic."""
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return {"rate": p, "k": int(k), "n": int(n), "ci95": [max(0.0, c - h), min(1.0, c + h)]}


def evaluate(bundle, res, truth, holdout, train_label_raw=None, rare=()):
    classes = bundle["feature_schema"]["classes"]
    label, ok = truth["label"], res["error"].isna()
    known = label.isin(classes) & ok
    v = res["verdict"]
    m = {}
    if known.any() and "predicted_class" in res:
        y, yp = label[known], res.loc[known, "predicted_class"]
        covered = [t in s for t, s in zip(y, res.loc[known, "conformal_set"])]
        m["closed_set_classifier_only"] = {
            "macro_f1": f1_score(y, yp, average="macro", labels=classes, zero_division=0),
            "balanced_accuracy": balanced_accuracy_score(y, yp),
            "per_class": classification_report(y, yp, labels=classes, output_dict=True, zero_division=0),
            "confusion_matrix": {"labels": classes, "matrix": confusion_matrix(y, yp, labels=classes).tolist()}}
        sizes = res.loc[known, "conformal_set"].map(len)
        m["conformal"] = {"empirical_coverage": float(np.mean(covered)),
                          "target_coverage": 1 - bundle["calibration"]["conformal"]["alpha"],
                          "per_class_coverage": {c: float(np.mean([t in s for t, s in zip(y[y == c], res.loc[y[y == c].index, "conformal_set"])]))
                                                 for c in classes if (y == c).any()},
                          "mean_set_size": float(sizes.mean()), "empty_set_rate": float((sizes == 0).mean()),
                          "calibration_counts": {c: q["n"] for c, q in bundle["calibration"]["conformal"]["classes"].items()},
                          "fallback_classes": [c for c, q in bundle["calibration"]["conformal"]["classes"].items()
                                               if q["insufficient_calibration_support"]]}
    ben = label.eq(BENIGN)
    nb = int(ben.sum())
    m["benign"] = {
        "auto_alert_fpr": wilson(int((ben & v.isin([core.KNOWN, core.UNKNOWN])).sum()), nb),
        "benign_review_rate": wilson(int((ben & v.isin([core.UNCERTAIN, core.DEGRADED, core.ERROR])).sum()), nb),
        "total_analyst_burden": wilson(int((ben & v.ne(core.NORMAL)).sum()), nb),
        "threshold_test_fpr": wilson(int((ben & res["novelty_triggered"].eq(True)).sum()), nb),
        "definitions": "auto-alert = KNOWN_ATTACK|UNKNOWN_ANOMALY; review = UNCERTAIN|DEGRADED|ERROR; "
                       "threshold FPR = novelty score > frozen threshold regardless of verdict",
    }
    m["benign"]["target_fpr"] = bundle["calibration"]["anomaly"]["target_fpr"]

    def open_world(mask):
        n = int(mask.sum())
        if not n:
            return None
        return {"n": n,
                "novelty_gate_recall": wilson(int((mask & res["novelty_triggered"].eq(True)).sum()), n),
                "system_alert_recall": wilson(int((mask & v.ne(core.NORMAL)).sum()), n),
                "assigned_known_attack_candidate": wilson(int((mask & v.eq(core.KNOWN)).sum()), n),
                "verdicts": {str(k): int(c) for k, c in v[mask].value_counts().items()},
                "known_candidates": {str(k): int(c) for k, c in res.loc[mask & v.eq(core.KNOWN), "known_attack_candidate"].value_counts().items()}}
    held = label.eq(holdout)
    m["lofo"] = {"holdout_family": holdout, **(open_world(held) or {"n": 0})}
    unk = v.eq(core.UNKNOWN)
    m["lofo"]["unknown_anomaly_precision"] = wilson(int((unk & held).sum()), int(unk.sum()))
    m["lofo"]["system_alert_rule"] = "alert-bearing = any verdict other than NORMAL (incl. review states)"
    m["rare_families_excluded_from_known_set"] = {f: open_world(label.eq(f)) for f in rare}
    if train_label_raw is not None:
        novel = ~truth["label_raw"].isin(train_label_raw) & ~ben
        m["attack_types_absent_from_training_file"] = open_world(novel)
        if novel.any():
            m["attack_types_absent_from_training_file"]["types"] = sorted(truth.loc[novel, "label_raw"].unique().tolist())
    attacks = ~ben
    alerts = v.ne(core.NORMAL)
    m["correlation"] = {"enabled": bool(res["incident_id"].notna().any() or res["burst"].notna().any()),
                        "raw_flow_alerts": int(alerts.sum()), "incident_groups": int(res["incident_id"].nunique()),
                        "flows_in_incidents": int(res["incident_id"].notna().sum()),
                        "attack_recall_before_grouping": float(alerts[attacks].mean()) if attacks.any() else None,
                        "attack_recall_after_grouping": float((alerts | res["incident_id"].notna())[attacks].mean()) if attacks.any() else None,
                        "note": "grouping never removes a flow alert; this is not a false-positive reduction claim"}
    m["hybrid_verdicts_by_true_label"] = {str(k): {str(c): int(n) for c, n in g.value_counts().items()}
                                          for k, g in v.groupby(label)}
    return m


def measure_performance(bundle, X, meta, res, batch=1000):
    lat = []
    tracemalloc.start()
    t0 = time.perf_counter()
    for i in range(0, len(X), batch):
        t = time.perf_counter()
        infer(bundle, X.iloc[i:i + batch], None if meta is None else meta.iloc[i:i + batch])
        lat.append((time.perf_counter() - t) * 1000)
    total = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    flagged = res.index[res["verdict"].ne(core.NORMAL)][:20]
    exp = [explain(bundle, X.loc[[i]], res.loc[i])["explanation_latency_ms"] for i in flagged]
    return {"flows": len(X), "batch_size": batch, "throughput_flows_per_s": len(X) / total,
            "batch_latency_ms_median": float(np.median(lat)), "per_flow_latency_ms": total * 1000 / len(X),
            "explanation_latency_ms_mean": float(np.mean(exp)) if exp else None,
            "explanation_included_in_throughput": False, "peak_python_memory_mb": peak / 2**20,
            "warm_up": "none; first batch included", "hardware": platform.processor()}
