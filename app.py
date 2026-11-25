"""Streamlit analyst dashboard. Start with:  streamlit run app.py"""
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from ids import core, pipeline

FEEDBACK = pipeline.ROOT / "feedback" / "feedback_log.jsonl"
BANNER = "OFFLINE DATASET REPLAY - labelled public-dataset records, not live network monitoring"

st.set_page_config(page_title="Open-World IDS", layout="wide")
st.error(f"**{BANNER}**")


@st.cache_resource
def load(path):
    return pipeline.load_bundle(path), joblib.load(Path(path) / "test_records.joblib")


def experiments():
    return sorted(p for p in pipeline.ARTIFACTS.glob("*/*") if (p / "run_manifest.json").exists())


def mask_ip(v):
    s = str(v)
    return s.rsplit(".", 2)[0] + ".*.*" if s.count(".") == 3 else s


exps = experiments()
if not exps:
    st.info("No model bundles yet. Train one first, e.g. `python run.py nsl_kdd --holdout Probe`.")
    st.stop()

with st.sidebar:
    path = st.selectbox("Dataset / experiment", exps, format_func=lambda p: f"{p.parent.name} / {p.name}")
    batch = st.slider("Replay batch size (flows per tick)", 50, 2000, 250, 50)
    tick = st.slider("Seconds per tick", 0.2, 5.0, 1.0, 0.2)
    masked = st.toggle("Mask IP addresses", True)

bundle, records = load(str(path))
X, meta = records["X"], records["meta"]  # ground truth stays in records["truth"], used only in Research Proof
schema, cal = bundle["feature_schema"], bundle["calibration"]
state = st.session_state.setdefault(str(path), {"cursor": 0, "running": False, "res": None,
                                                "run_id": time.strftime("run-%Y%m%d-%H%M%S")})


def step():
    i = state["cursor"]
    if i >= len(X):
        state["running"] = False
        return
    j = min(i + batch, len(X))
    new = pipeline.infer(bundle, X.iloc[i:j], meta.iloc[i:j])
    res = new if state["res"] is None else pd.concat([state["res"], new])
    state["res"] = pipeline.correlate_and_prioritize(bundle, res, meta.loc[res.index])
    state["cursor"] = j


tab_ops, tab_triage, tab_proof = st.tabs(["Operations Monitor", "Alert Triage", "Research Proof"])

with tab_ops:
    c = st.columns(4)
    if c[0].button("Start / Resume", type="primary"):
        state["running"] = True
    if c[1].button("Pause"):
        state["running"] = False
    if c[2].button("Reset"):
        state.update(cursor=0, running=False, res=None, run_id=time.strftime("run-%Y%m%d-%H%M%S"))
    if c[3].button("Step one batch"):
        step()

    @st.fragment(run_every=tick if state["running"] else None)
    def monitor():
        if state["running"]:
            step()
        res = state["res"]
        st.caption(f"Dataset **{schema['dataset']}** | experiment **{path.name}** | replay run **{state['run_id']}** | "
                   f"{state['cursor']:,} / {len(X):,} flows | {'running' if state['running'] else 'paused'} | {BANNER}")
        if res is None:
            st.info("Press Start to replay the frozen test partition through the deployed bundle.")
            return
        v = res["verdict"].value_counts()
        m = st.columns(6)
        m[0].metric("Flows", f"{len(res):,}")
        m[1].metric("Normal candidates", int(v.get(core.NORMAL, 0)))
        m[2].metric("Known attacks", int(v.get(core.KNOWN, 0)))
        m[3].metric("Unknown anomalies", int(v.get(core.UNKNOWN, 0)))
        m[4].metric("Uncertain / degraded / error",
                    int(v.get(core.UNCERTAIN, 0) + v.get(core.DEGRADED, 0) + v.get(core.ERROR, 0)))
        m[5].metric("Correlated incident groups", int(res["incident_id"].nunique()))
        tail = res.tail(3000).reset_index(names="flow")
        fig = px.scatter(tail, x="flow", y="anomaly_score", color="verdict", height=340,
                         title="Anomaly score (higher = more unusual) vs frozen calibration threshold")
        if cal["anomaly"]["threshold"] is not None:
            fig.add_hline(y=cal["anomaly"]["threshold"], line_dash="dash",
                          annotation_text=f"threshold (target benign FPR {cal['anomaly']['target_fpr']:.0%})")
        st.plotly_chart(fig)
        drift = core.psi(schema["psi_baseline"], X.loc[res.index[-2000:]])
        st.write(f"**Drift (PSI, last {drift['batch_size']} flows):** {drift['status']}"
                 + (f" - max PSI {drift['max_psi']:.3f}" if drift["features"] else "")
                 + "  \nPSI shows distribution change only. It never changes verdicts or retrains.")
        if drift["features"]:
            st.bar_chart(pd.Series(drift["features"], name="PSI"), height=200)

    monitor()

with tab_triage:
    res = state["res"]
    if res is None:
        st.info("Replay some flows in the Operations Monitor first.")
    else:
        f = st.columns(3)
        pick = f[0].multiselect("Verdict", core.VERDICTS, [v for v in core.VERDICTS if v != core.NORMAL])
        novelty_only = f[1].checkbox("Novelty-triggered only")
        min_p = f[2].slider("Min triage priority (heuristic)", 0, 100, 0)
        view = res[res["verdict"].isin(pick) & (res["priority"].fillna(100) >= min_p)]
        if novelty_only:
            view = view[view["novelty_triggered"].eq(True)]
        m = meta.loc[view.index]
        table = pd.DataFrame({
            "flow": view.index, "verdict": view["verdict"], "candidate": view["known_attack_candidate"],
            "conformal_set": view["conformal_set"].map(lambda s: ", ".join(s) if isinstance(s, list) else "n/a"),
            "novelty_conflict": view["novelty_conflict"], "anomaly_score": view["anomaly_score"].round(4),
            "priority": view["priority"].round(1), "band": view["priority_band"], "incident": view["incident_id"],
        }, index=view.index)
        for col in ["timestamp", "source_ip", "destination_ip"]:
            if col in m:
                table[col] = m[col].map(mask_ip) if masked and col.endswith("ip") else m[col]
        table = table.sort_values("priority", ascending=False, na_position="first")
        st.caption(f"{len(table):,} flows match. Every flow stays listed; incident grouping only adds context. "
                   "Priority is a triage heuristic, not a probability of attack.")
        sel = st.dataframe(table, hide_index=True, on_select="rerun", selection_mode="single-row",
                           width="stretch", height=320)
        rows = sel.selection.rows
        if rows:
            idx = table.index[rows[0]]
            row, mrow = res.loc[idx], meta.loc[idx]
            left, right = st.columns(2)
            with left:
                st.subheader(f"Flow {idx}: {row['verdict']}")
                if row["novelty_conflict"]:
                    st.warning("Novelty conflict: classifier names a known attack but traffic is also unusual. Review.")
                why = {core.NORMAL: "benign is the only plausible class and the novelty gate did not trigger.",
                       core.KNOWN: "exactly one known attack class remained plausible in the conformal set.",
                       core.UNKNOWN: "the novelty gate triggered and no single known attack class explains the flow.",
                       core.UNCERTAIN: "the conformal set was empty or ambiguous and the novelty gate did not trigger.",
                       core.DEGRADED: "a required model signal was unavailable.",
                       core.ERROR: f"input failed validation: {row['error']}"}
                st.write("**Why this verdict:** " + why[row["verdict"]])
                rec = pipeline.to_contract(bundle, row, mrow, path.name, f"replay-{idx}")
                if masked:
                    rec["metadata"] = {k: mask_ip(v) if k.endswith("ip") and v else v for k, v in rec["metadata"].items()}
                st.json(rec, expanded=False)
            with right:
                if st.button("Explain this flow"):
                    exp = pipeline.explain(bundle, X.loc[[idx]], row)
                    st.write(f"**Suggested defensive step (for a human analyst):** {exp['defensive_action']}")
                    shap_out = exp["shap"]
                    if shap_out.get("top_features"):
                        d = pd.DataFrame(shap_out["top_features"])
                        st.plotly_chart(go.Figure(go.Bar(x=d["contribution"], y=d["feature"], orientation="h")).update_layout(
                            title=f"{shap_out['method']} - class {shap_out['explained_class']}", height=260),
                            )
                    else:
                        st.caption(f"SHAP unavailable: {shap_out.get('reason')}")
                    st.write("**Benign baseline deviation** (diagnostic, not SHAP, not causal)")
                    st.dataframe(pd.DataFrame(exp["baseline_deviation"]).drop(columns="method"), hide_index=True)
                    st.caption(f"Explanation latency {exp['explanation_latency_ms']:.0f} ms (separate from inference).")
                with st.form(f"fb{idx}"):
                    action = st.radio("Analyst feedback", ["verified-benign", "suspected-attack", "needs-more-investigation"])
                    note = st.text_input("Note (optional)", max_chars=500)
                    if st.form_submit_button("Record feedback"):
                        FEEDBACK.parent.mkdir(exist_ok=True)
                        with open(FEEDBACK, "a", encoding="utf-8") as fh:  # append-only; never feeds training
                            fh.write(json.dumps({"alert_id": f"{state['run_id']}/replay-{idx}", "experiment": path.name,
                                                 "model_version": schema["bundle_version"], "verdict": row["verdict"],
                                                 "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                                 "reviewer_action": action, "note": note}) + "\n")
                        st.success("Recorded in the audit log. Models and thresholds are unchanged.")

with tab_proof:
    def pct(d):
        return None if not d else round(100 * d["rate"], 2)

    for ds in sorted({p.parent.name for p in exps}):
        st.header({"cic_ids2017": "CIC-IDS2017 (primary)", "nsl_kdd": "NSL-KDD (secondary benchmark)"}.get(ds, ds))
        rows = []
        for p in [e for e in exps if e.parent.name == ds]:
            mt = json.loads((p / "metrics.json").read_text())
            t, perf = mt["test"], mt["performance"]
            cs = t.get("closed_set_classifier_only", {})
            rows.append({"experiment": p.name, "macro_F1": cs.get("macro_f1"), "balanced_acc": cs.get("balanced_accuracy"),
                         "conformal_coverage": t.get("conformal", {}).get("empirical_coverage"),
                         "benign_auto_alert_FPR_%": pct(t["benign"]["auto_alert_fpr"]),
                         "benign_review_rate_%": pct(t["benign"]["benign_review_rate"]),
                         "threshold_test_FPR_%": pct(t["benign"]["threshold_test_fpr"]),
                         "heldout": t["lofo"]["holdout_family"],
                         "heldout_novelty_recall_%": pct(t["lofo"].get("novelty_gate_recall")),
                         "heldout_alert_recall_%": pct(t["lofo"].get("system_alert_recall")),
                         "unknown_anomaly_precision_%": pct(t["lofo"].get("unknown_anomaly_precision")),
                         "flows_per_s": round(perf["throughput_flows_per_s"]),
                         "explain_ms": perf["explanation_latency_ms_mean"]})
        st.dataframe(pd.DataFrame(rows).round(3), hide_index=True, width="stretch")
        st.caption("Compare *-grouped vs *-random rows for split optimism, and *-noport rows for the port ablation. "
                   "Held-out families are unseen during this model's training/calibration; this is not real-world zero-day detection.")

    st.divider()
    mt = bundle["metrics"]
    t = mt["test"]
    st.subheader(f"Detail: {schema['dataset']} / {path.name}")
    if "closed_set_classifier_only" in t:
        cm = t["closed_set_classifier_only"]["confusion_matrix"]
        st.plotly_chart(px.imshow(np.array(cm["matrix"]), x=cm["labels"], y=cm["labels"], text_auto=True,
                                  labels={"x": "predicted", "y": "true"}, title="Classifier-only confusion matrix (known classes)"),
                        )
        st.dataframe(pd.DataFrame(t["closed_set_classifier_only"]["per_class"]).T.round(3))
    st.write("**Hybrid verdicts by true label**")
    st.dataframe(pd.DataFrame(t["hybrid_verdicts_by_true_label"]).T.fillna(0).astype(int))
    st.write("**Open-world results**")
    st.json({"held_out_family": t["lofo"], "rare_families_excluded_from_known_set": t.get("rare_families_excluded_from_known_set"),
             "attack_types_absent_from_training_file": t.get("attack_types_absent_from_training_file")}, expanded=False)
    st.write("**Conformal calibration and benign burden**")
    st.json({"conformal": t.get("conformal"), "benign": t["benign"],
             "anomaly_threshold": {k: v for k, v in cal["anomaly"].items() if k != "reference_scores"}}, expanded=False)
    st.write("**Temporal correlation (raw flow alerts vs grouped incidents)**")
    st.json(t["correlation"], expanded=False)
    st.write("**Leakage audit**")
    st.json(mt["leakage_audit"] | {"data_quality": {k: v for k, v in mt["data_quality"].items()
                                                     if k not in ("quarantined_row_ids_sample", "label_variants")}},
            expanded=False)
    st.write("**Operational performance**")
    st.json(mt["performance"], expanded=False)
