"""Run one experiment end to end and write a versioned bundle to artifacts/<dataset>/<experiment_id>/.

  python run.py nsl_kdd --holdout Probe
  python run.py nsl_kdd --holdout Probe --split random          # leakage/optimism audit
  python run.py cic_ids2017 --holdout PortScan --max-rows-per-class 50000
  python run.py cic_ids2017 --holdout PortScan --no-port         # Destination Port ablation
"""
import argparse
import json

import numpy as np

from ids import core, data, pipeline

RAW = {"nsl_kdd": pipeline.ROOT / "data/raw/nsl_kdd", "cic_ids2017": pipeline.ROOT / "data/raw/cic_ids2017"}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", choices=list(RAW))
    ap.add_argument("--holdout", required=True, help="attack family held out of training/validation/conf_cal")
    ap.add_argument("--split", choices=["grouped", "random"], default="grouped")
    ap.add_argument("--no-port", action="store_true", help="CIC: drop destination_port from features")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--alpha", type=float, default=0.05, help="conformal miscoverage")
    ap.add_argument("--beta", type=float, default=0.01, help="target benign FPR for the novelty gate")
    ap.add_argument("--max-rows-per-class", type=int, help="CIC: deterministic per-class sample")
    ap.add_argument("--trees", type=int, default=200)
    ap.add_argument("--raw-dir", help="override raw data directory")
    args = vars(ap.parse_args(argv))
    raw = args.pop("raw_dir") or RAW[args["dataset"]]

    if args["dataset"] == "nsl_kdd":
        df, info, report = data.load_nsl(raw)
    else:
        df, info, report = data.load_cic(raw, args["max_rows_per_class"], args["seed"])
    if args["no_port"]:
        info["features"] = [c for c in info["features"] if c != "destination_port"]
        info["numeric"] = [c for c in info["numeric"] if c != "destination_port"]
        report["excluded_columns"].append("destination_port")
    if args["holdout"] not in set(df["label"]) - {data.BENIGN}:
        raise SystemExit(f"--holdout must be an attack family in the data: {sorted(set(df['label']) - {data.BENIGN})}")
    args["experiment_id"] = f"lofo-{args['holdout'].lower()}-{args['split']}" + ("-noport" if args["no_port"] else "")
    print(f"[{args['dataset']}] {args['experiment_id']}: {len(df)} rows after quarantine")

    rare = data.rare_families(df, args["holdout"], args["alpha"])
    part = data.make_split(df, args["holdout"], args["seed"], args["split"], args["alpha"])
    audit = data.audit_split(df, part, args["holdout"], rare)
    assert all(v for k, v in audit["checks"].items() if k != "anom_cal_conf_cal_row_overlap"), audit["checks"]
    if args["dataset"] == "cic_ids2017":
        audit["limitations"] = ("Source-file/day-aware grouping is infeasible: CIC attack families are confined to "
                                "single capture days, so a file-level split would drop classes. Grouping is by "
                                "feature-vector fingerprint; no temporal-generalisation claim is made.")
    else:
        audit["limitations"] = ("Official KDDTest+ boundary preserved; identical feature vectors across official "
                                "train/test cannot be moved and are reported in feature_vector_overlap.")

    bundle = pipeline.train(df, part, info, args["holdout"], args["seed"], args["alpha"], args["beta"], args["trees"])
    feats, meta_cols = info["features"], info["metadata"] + ["session"]
    schema = bundle["feature_schema"]

    # Validation: select display bands only (weights stay provisional placeholders).
    val = df[part == "validation"]
    vres = pipeline.infer(bundle, val[feats], val[meta_cols])
    schema["priority_band_cutoffs"] = np.nanquantile(vres["priority"], [.5, .8, .95]).tolist()
    val_metrics = pipeline.evaluate(bundle, vres, val[["label", "label_raw"]], args["holdout"])

    # Everything is frozen from here; the test partition is scored exactly once.
    test = df[part == "test"].sort_values(["session", "timestamp"] if "timestamp" in df else ["row_id"], kind="stable")
    X, meta, truth = test[feats], test[meta_cols], test[["label", "label_raw"]]
    res = pipeline.infer(bundle, X, meta)
    train_raw = set(df.loc[df["official_split"].eq("official_train"), "label_raw"]) if "official_split" in df else None
    metrics = {"test": pipeline.evaluate(bundle, res, truth, args["holdout"], train_raw, rare),
               "validation": val_metrics,
               "performance": pipeline.measure_performance(bundle, X, meta, res),
               "data_quality": report, "leakage_audit": audit,
               "test_verdict_counts": {str(k): int(v) for k, v in res["verdict"].value_counts().items()}}
    metrics["test"]["psi_first_2000_test_rows"] = core.psi(schema["psi_baseline"], X.iloc[:2000])
    bundle["metrics"] = metrics
    bundle["split_manifest"] = data.split_manifest(df, part, args["split"], args["seed"], args["holdout"], rare)
    bundle["run_manifest"] = pipeline.run_manifest(info, report, args, report["provenance"])
    out = pipeline.ARTIFACTS / args["dataset"] / args["experiment_id"]
    first = res.index[0]
    example = pipeline.to_contract(bundle, res.loc[first], meta.loc[first], args["experiment_id"], f"replay-{first}")
    bundle["metrics"]["example_output"] = example
    pipeline.save_bundle(out, bundle, {"test_records.joblib": {"X": X, "meta": meta, "truth": truth}})

    t = metrics["test"]
    print(json.dumps(pipeline._json_clean({
        "closed_set_macro_f1": t.get("closed_set_classifier_only", {}).get("macro_f1"),
        "conformal_coverage": t.get("conformal", {}).get("empirical_coverage"),
        "benign_auto_alert_fpr": t["benign"]["auto_alert_fpr"]["rate"],
        "threshold_test_fpr": t["benign"]["threshold_test_fpr"]["rate"],
        "heldout_novelty_recall": (t["lofo"].get("novelty_gate_recall") or {}).get("rate"),
        "heldout_system_alert_recall": (t["lofo"].get("system_alert_recall") or {}).get("rate"),
        "verdicts": metrics["test_verdict_counts"], "bundle": str(out)}), indent=1))


if __name__ == "__main__":
    main()
