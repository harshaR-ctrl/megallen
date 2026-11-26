"""Detection console backend.  python server.py  ->  http://127.0.0.1:8000

A background worker scores (a) the frozen test partition as an offline replay and (b) the live inbox that
inject.py / the console's simulation panel write to. Results stream to the browser over server-sent events.
Bound to localhost only: this is an offline research demonstrator, not a network sensor.
"""
import asyncio
import os
import json
import threading
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import plotly
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ids import core, glossary, live, pipeline

WEB = pipeline.ROOT / "web"
FEEDBACK = pipeline.ROOT / "feedback" / "feedback_log.jsonl"
MAX_EVENTS = 40_000
WINDOW = 3_000  # rows re-correlated per source on each update
STATUSES = ["new", "investigating", "escalated", "resolved", "false_positive"]
WHY = {core.NORMAL: "Benign is the only plausible known class and the novelty gate did not trigger.",
       core.KNOWN: "Exactly one known attack class remained plausible in the conformal set.",
       core.UNKNOWN: "The novelty gate triggered and no single known attack class explains the flow - "
                     "behaviour unlike the benign baseline and unlike any trained attack.",
       core.UNCERTAIN: "The conformal set was empty or ambiguous and the novelty gate did not trigger.",
       core.DEGRADED: "A required model signal was unavailable, so no normal verdict was possible.",
       core.ERROR: "The record failed schema validation; no model was run on it."}


def bundles():
    return sorted(f"{p.parent.name}/{p.name}" for p in pipeline.ARTIFACTS.glob("*/*") if (p / "run_manifest.json").exists())


def _num(v):
    return None if v is None or (isinstance(v, float) and not np.isfinite(v)) or pd.isna(v) else float(v)


def flow_summary(x):
    """Protocol, duration, packets and bytes of one flow, using whichever dataset's columns are present."""
    g = lambda *cols: next((x[c] for c in cols if c in x and not pd.isna(x[c])), None)  # noqa: E731
    n = lambda *cols: _num(pd.to_numeric(g(*cols), errors="coerce"))  # malformed records may carry strings  # noqa: E731
    dur = n("duration")
    if dur is None and (us := n("flow_duration")) is not None:
        dur = us / 1e6  # CIC reports microseconds
    pk_out, pk_back = n("total_fwd_packets"), n("total_backward_packets")
    by_out, by_back = n("src_bytes", "total_length_of_fwd_packets"), n("dst_bytes", "total_length_of_bwd_packets")
    proto, port = g("protocol_type", "protocol"), n("destination_port")
    return {"protocol": None if proto is None else str(proto), "service": None if (sv := g("service")) is None else str(sv),
            "port": None if port is None else int(port), "flag": None if (fl := g("flag")) is None else str(fl),
            "duration_s": dur, "packets_out": pk_out, "packets_back": pk_back,
            "packets": None if pk_out is None and pk_back is None else (pk_out or 0) + (pk_back or 0),
            "bytes_out": by_out, "bytes_back": by_back,
            "bytes": None if by_out is None and by_back is None else (by_out or 0) + (by_back or 0)}


class Engine:
    def __init__(self):
        self.lock = threading.RLock()
        names = bundles()
        if not names:
            raise SystemExit("No model bundles. Train one first: python run.py nsl_kdd --holdout Probe")
        self.load("nsl_kdd/lofo-probe-grouped" if "nsl_kdd/lofo-probe-grouped" in names else names[0])

    def load(self, name):
        if name not in bundles():
            raise HTTPException(404, "unknown bundle")
        path = pipeline.ARTIFACTS / name
        bundle, records = pipeline.load_bundle(path), joblib.load(path / "test_records.joblib")
        with self.lock:
            self.name, self.bundle, self.records = name, bundle, records
            self.schema, self.cal = bundle["feature_schema"], bundle["calibration"]
            self.events, self.detail, self.order = {}, {}, []
            self.by_ref = {}  # inbox event_id -> console event id, so inject.py can show the dashboard's verdict
            self.frames = {"replay": None, "live": None}
            self.next_id, self.cursor, self.running, self.rate = 1, 0, False, 200
            self.offset = live.INBOX.stat().st_size if live.INBOX.exists() else 0
            self.started = time.time()
            self.recent_X, self.drift, self.drift_at = None, {"status": "insufficient_batch", "features": {}}, 0
            self.mismatch = set()  # experiments named by injected events that differ from the loaded model

    # ---------- ingest ----------
    def _ingest(self, source, X, meta, res, scenario=None):
        eids = pd.Index(range(self.next_id, self.next_id + len(res)))
        self.next_id += len(res)
        if source == "live":
            self.by_ref.update(zip(map(str, res.index), map(int, eids)))
        X = X.loc[res.index].set_axis(eids)  # align by the original row/event index, then re-key
        res, meta = res.set_axis(eids), meta.loc[res.index].set_axis(eids)
        num = X.reindex(columns=self.schema["numeric"]).apply(pd.to_numeric, errors="coerce")
        self.recent_X = pd.concat([self.recent_X, num]).tail(2000) if self.recent_X is not None else num
        prev = self.frames[source]
        frame = (res, meta) if prev is None else (pd.concat([prev[0], res]).tail(WINDOW), pd.concat([prev[1], meta]).tail(WINDOW))
        corr = pipeline.correlate_and_prioritize(self.bundle, frame[0].copy(), frame[1])
        self.frames[source] = (corr, frame[1])
        now = time.time()
        for eid in corr.index:  # refresh priority/incident of recent rows, add new ones
            row = corr.loc[eid]
            if eid in self.events:
                self.events[eid].update(priority=_num(row["priority"]), band=row["priority_band"],
                                        incident=row["incident_id"] if isinstance(row["incident_id"], str) else None)
                continue
            m = meta.loc[eid]
            sc = m.get("scenario") if scenario is None else scenario
            v = row["verdict"]
            self.events[eid] = {
                "id": int(eid), "t": now, "source": source, "scenario": sc if isinstance(sc, str) else None,
                "src": None if pd.isna(m.get("source_ip")) else str(m.get("source_ip")),
                "dst": None if pd.isna(m.get("destination_ip")) else str(m.get("destination_ip")),
                "verdict": v, "candidate": row["known_attack_candidate"],
                "set": row["conformal_set"] if isinstance(row["conformal_set"], list) else None,
                "conflict": bool(row["novelty_conflict"]), "novelty": None if row["novelty_triggered"] is None else bool(row["novelty_triggered"]),
                "score": _num(row["anomaly_score"]), "priority": _num(row["priority"]), "band": row["priority_band"],
                "incident": row["incident_id"] if isinstance(row["incident_id"], str) else None,
                "error": row["error"], "status": None if v == core.NORMAL else "new", "history": [],
                "flow": flow_summary(X.loc[eid])}
            self.detail[eid] = (X.loc[[eid]], row, m)
            self.order.append(eid)
        while len(self.order) > MAX_EVENTS:
            old = self.order.pop(0)
            self.events.pop(old, None), self.detail.pop(old, None)
        if len(self.by_ref) > MAX_EVENTS:
            self.by_ref = {r: i for r, i in self.by_ref.items() if i in self.events}

    def tick(self, dt):
        with self.lock:
            if self.running and self.cursor < len(self.records["X"]):
                n = max(1, int(self.rate * dt))
                i, j = self.cursor, min(self.cursor + n, len(self.records["X"]))
                X = self.records["X"].iloc[i:j]
                meta = self.records["meta"].iloc[i:j]
                res = pipeline.infer(self.bundle, X, meta)
                self._ingest("replay", X, meta, res)
                self.cursor = j
                self.running = j < len(self.records["X"])
            events, self.offset = live.read_new(self.offset)
            events = [e for e in events if e.get("dataset") in (None, self.schema["dataset"])]
            self.mismatch |= {e["experiment"] for e in events if e.get("experiment") not in (None, self.name)}
            if events:
                res, meta = live.score(self.bundle, events)
                X = pd.concat([pd.DataFrame([e["features"]], index=[e["event_id"]]) for e in events])
                self._ingest("live", X, meta, res)

    # ---------- views ----------
    def state(self):
        with self.lock:
            ev = [self.events[i] for i in self.order]
            now = time.time()
            counts = {v: 0 for v in core.VERDICTS}
            status = {s: 0 for s in STATUSES}
            for e in ev:
                counts[e["verdict"]] += 1
                if e["status"]:
                    status[e["status"]] += 1
            if self.recent_X is not None and now - self.drift_at > 5:  # PSI over the last 2,000 scored flows
                self.drift, self.drift_at = core.psi(self.schema["psi_baseline"], self.recent_X), now
            drift = self.drift
            return {
                "bundle": self.name, "bundles": bundles(), "dataset": self.schema["dataset"],
                "holdout": self.schema["holdout_family"], "classes": self.schema["classes"],
                "threshold": self.cal["anomaly"]["threshold"], "target_fpr": self.cal["anomaly"]["target_fpr"],
                "alpha": self.cal["conformal"]["alpha"],
                "replay": {"cursor": self.cursor, "total": len(self.records["X"]), "running": self.running, "rate": self.rate},
                "counts": counts, "status": status, "total": len(ev),
                "incidents": len({e["incident"] for e in ev if e["incident"]}),
                "eps": sum(1 for e in ev[-5000:] if now - e["t"] < 10) / 10,
                "drift": {"status": drift["status"], "max_psi": drift.get("max_psi"),
                          "features": dict(sorted(drift.get("features", {}).items(), key=lambda kv: -kv[1])[:8]),
                          "described": {f: glossary.describe(f) for f in drift.get("features", {})}},
                "last_id": self.next_id - 1, "mismatch": sorted(self.mismatch)}

    def since(self, last_id, limit=1500):
        with self.lock:
            out = [self.events[i] for i in self.order if i > last_id]
            return [_slim(e) for e in out[-limit:]]


def _slim(e):
    return {k: v for k, v in e.items() if k != "history"}


engine = Engine()


def worker():
    last = time.time()
    while True:
        time.sleep(0.4)
        now = time.time()
        try:
            engine.tick(now - last)
        except Exception as exc:  # noqa: BLE001 - keep the console alive; the error is visible in the log
            print("worker error:", exc)
        last = now


app = FastAPI(title="Megallen console", docs_url="/api/docs")


class ReplayCmd(BaseModel):
    action: str = Field(pattern="^(start|pause|reset)$")
    rate: int | None = Field(default=None, ge=10, le=5000)


class InjectCmd(BaseModel):
    scenario: str = Field(pattern="^(normal|zero-day|attack|mix|known|synthetic|benign|malformed)$")
    attack: str | None = Field(default=None, pattern="^[A-Za-z0-9_]{1,40}$")
    count: int = Field(default=25, ge=1, le=500)
    rate: float = Field(default=10, ge=0, le=200)
    zero_day_share: float = Field(default=0.15, ge=0, le=1)
    attack_share: float = Field(default=0.15, ge=0, le=1)


class TriageCmd(BaseModel):
    status: str = Field(pattern="^(new|investigating|escalated|resolved|false_positive)$")
    note: str = Field(default="", max_length=500)


class BundleCmd(BaseModel):
    bundle: str = Field(max_length=200)


@app.get("/api/state")
def get_state():
    return engine.state()


@app.post("/api/bundle")
def set_bundle(cmd: BundleCmd):
    engine.load(cmd.bundle)
    return engine.state()


@app.post("/api/replay")
def replay(cmd: ReplayCmd):
    with engine.lock:
        if cmd.rate:
            engine.rate = cmd.rate
        if cmd.action == "start":
            engine.running = engine.cursor < len(engine.records["X"])
        elif cmd.action == "pause":
            engine.running = False
        else:
            engine.load(engine.name)
    return engine.state()["replay"]


def _novel_types():
    return (engine.bundle["metrics"]["test"].get("attack_types_absent_from_training_file") or {}).get("types", [])


@app.get("/api/attack-types")
def attack_types():
    with engine.lock:
        return {"holdout": engine.schema["holdout_family"], "types": live.attack_catalog(engine.schema, engine.records, _novel_types()),
                "status_text": live.STATUS_TEXT}


@app.post("/api/inject")
def inject(cmd: InjectCmd):
    if cmd.zero_day_share + cmd.attack_share > 1:
        raise HTTPException(422, "zero_day_share + attack_share must be at most 1")
    with engine.lock:
        try:
            items = live.plan_items(engine.schema, engine.records, cmd.scenario, cmd.count, np.random.default_rng(), cmd.attack,
                                    _novel_types(), (1 - cmd.zero_day_share - cmd.attack_share, cmd.zero_day_share, cmd.attack_share))
        except ValueError as e:
            raise HTTPException(400, str(e))
        dataset, exp = engine.schema["dataset"], engine.name
    threading.Thread(target=live.stream_items, args=(items, dataset, cmd.rate), kwargs={"experiment": exp}, daemon=True).start()
    kinds = {}
    for _, name, _ in items:
        k = name.split(":")[0].split(" (")[0]
        kinds[k] = kinds.get(k, 0) + 1
    return {"queued": len(items), "scenario": cmd.scenario, "attack": cmd.attack, "breakdown": kinds}


@app.get("/api/verdicts")
def verdicts(refs: str = ""):
    """Dashboard verdicts for flows sent by inject.py, looked up by their inbox event ids."""
    wanted = [r for r in refs.split(",") if r][:200]
    with engine.lock:
        out = {}
        for r in wanted:
            eid = engine.by_ref.get(r)
            if eid in engine.events:
                e = engine.events[eid]
                out[r] = {"id": eid, "verdict": e["verdict"], "candidate": e["candidate"]}
        return {"bundle": engine.name, "verdicts": out}


@app.get("/api/events")
def list_events(verdict: str = "", status: str = "", source: str = "", q: str = "", limit: int = 500):
    with engine.lock:
        ev = [engine.events[i] for i in reversed(engine.order)]
    verdicts, statuses = set(filter(None, verdict.split(","))), set(filter(None, status.split(",")))
    out = []
    for e in ev:
        if verdicts and e["verdict"] not in verdicts or statuses and (e["status"] or "") not in statuses or source and e["source"] != source:
            continue
        if q and q.lower() not in json.dumps(_slim(e)).lower():
            continue
        out.append(_slim(e))
        if len(out) >= min(limit, 2000):
            break
    return out


def rule_for(e):
    """Which row of the decision table (architecture.md 6.4) produced this verdict."""
    v, nov, cset = e["verdict"], e["novelty"], e["set"] or []
    if v in (core.ERROR, core.DEGRADED):
        return 7
    if v == core.KNOWN:
        return 2 if nov else 1
    if v == core.NORMAL:
        return 3
    if v == core.UNKNOWN:
        return 4 if cset == [core.BENIGN] else 5
    return 6


def summary(e, scores, thr):
    """One plain-English sentence on why this verdict was given."""
    s = e["score"]
    known = {c: p for c, p in scores.items() if p is not None}
    top = max(known, key=known.get) if known else None
    guess = f"The classifier's best guess was {top} ({known[top]:.0%})" if top else ""
    fits = e["set"] or []
    fit_txt = "no known class" if not fits else ("only " + ", ".join(fits)) if len(fits) == 1 else "several classes (" + ", ".join(fits) + ")"
    v = e["verdict"]
    if v == core.ERROR:
        return f"This record could not be checked: {e['error']}. It was not scored, and it was not marked normal."
    if v == core.DEGRADED:
        return "One of the two models was unavailable, so the system refused to call this flow normal."
    above = f"its unusualness score {s:.3f} is above the alert line {thr:.3f}"
    below = f"its unusualness score {s:.3f} is below the alert line {thr:.3f}"
    if v == core.UNKNOWN:
        return (f"Flagged as a possible zero-day: {above}, and {fit_txt} fit it with enough confidence. "
                f"{guess}, which is not enough to name a known attack.")
    if v == core.KNOWN:
        txt = f"Matched one known attack: {e['candidate']} ({known.get(e['candidate'], 0):.0%})."
        return txt + (f" But {above}, so it may be a new variant. Review it." if e["conflict"] else f" Also, {below}.")
    if v == core.NORMAL:
        return f"Looks normal: {below}, and only BENIGN fit it with enough confidence."
    return (f"Not unusual enough to alert ({below}), but the classifier could not settle on one class: {fit_txt} fit. "
            "A person should take a look.")


@app.get("/api/events/{eid}")
def event_detail(eid: int):
    with engine.lock:
        if eid not in engine.events:
            raise HTTPException(404, "event not retained")
        e, (X, row, meta) = engine.events[eid], engine.detail[eid]
        contract = pipeline.to_contract(engine.bundle, row, meta, engine.name, f"evt-{eid}")
        thr = engine.cal["anomaly"]["threshold"]
        q = engine.cal["conformal"]["classes"]
    scores = contract["signals"]["classifier_scores"]
    return {"event": e, "why": WHY[e["verdict"]], "summary": summary(e, scores, thr if thr is not None else float("inf")),
            "rule": rule_for(e), "contract": contract, "scores": scores, "threshold": thr,
            "pass_marks": {c: 1 - v["q"] for c, v in q.items()}}


@app.get("/api/events/{eid}/explain")
def explain(eid: int):
    with engine.lock:
        if eid not in engine.events:
            raise HTTPException(404, "event not retained")
        X, row, _ = engine.detail[eid]
        if engine.events[eid]["verdict"] == core.ERROR:
            return {"shap": {"method": "unavailable", "reason": "the record failed validation, so no model ran on it"},
                    "baseline_deviation": [], "defensive_action": pipeline.HINTS[core.ERROR]}
        out = pipeline._json_clean(pipeline.explain(engine.bundle, X[engine.schema["features"]], row))
    for t in (out.get("shap") or {}).get("top_features") or []:
        t["description"] = glossary.describe(t["feature"])
    for d in out.get("baseline_deviation", []):
        d["description"] = glossary.describe(d["feature"])
    return out


@app.get("/api/model")
def model_info():
    with engine.lock:
        schema, cal = engine.schema, engine.cal
        imp = sorted(schema["feature_importance"]["values"].items(), key=lambda t: -t[1])[:15]
        rare = engine.bundle["metrics"]["test"].get("rare_families_excluded_from_known_set") or {}
        return pipeline._json_clean({
            "bundle": engine.name, "dataset": schema["dataset"], "holdout": schema["holdout_family"], "classes": schema["classes"],
            "rare": list(rare), "n_features": len(schema["features"]),
            "threshold": cal["anomaly"]["threshold"], "target_fpr": cal["anomaly"]["target_fpr"], "n_anom_cal": cal["anomaly"]["n"],
            "alpha": cal["conformal"]["alpha"],
            "classes_cal": {c: {"pass_mark": 1 - v["q"], "n": v["n"], "fallback": v["insufficient_calibration_support"]}
                            for c, v in cal["conformal"]["classes"].items()},
            "importance": [{"feature": f, "importance": float(w), "description": glossary.describe(f)} for f, w in imp]})


@app.post("/api/events/{eid}/triage")
def triage(eid: int, cmd: TriageCmd):
    with engine.lock:
        if eid not in engine.events:
            raise HTTPException(404, "event not retained")
        e = engine.events[eid]
        entry = {"alert_id": f"{engine.name}/evt-{eid}", "model_version": engine.schema["bundle_version"],
                 "verdict": e["verdict"], "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                 "reviewer_action": cmd.status, "note": cmd.note}
        FEEDBACK.parent.mkdir(exist_ok=True)
        with open(FEEDBACK, "a", encoding="utf-8") as f:  # append-only audit log; never used for training
            f.write(json.dumps(entry) + "\n")
        e["status"] = cmd.status
        e["history"].append(entry)
        return e


@app.get("/api/metrics")
def metrics():
    rows = []
    for name in bundles():
        m = json.loads((pipeline.ARTIFACTS / name / "metrics.json").read_text())
        t, cs = m["test"], m["test"].get("closed_set_classifier_only", {})
        r = lambda d: None if not d else d["rate"]  # noqa: E731
        rows.append({"bundle": name, "holdout": t["lofo"]["holdout_family"], "macro_f1": cs.get("macro_f1"),
                     "balanced_acc": cs.get("balanced_accuracy"), "coverage": t.get("conformal", {}).get("empirical_coverage"),
                     "auto_alert_fpr": r(t["benign"]["auto_alert_fpr"]), "review_rate": r(t["benign"]["benign_review_rate"]),
                     "novelty_recall": r(t["lofo"].get("novelty_gate_recall")),
                     "alert_recall": r(t["lofo"].get("system_alert_recall")),
                     "unknown_precision": r(t["lofo"].get("unknown_anomaly_precision")),
                     "flows_per_s": m["performance"]["throughput_flows_per_s"]})
    with engine.lock:
        m = engine.bundle["metrics"]
    t = m["test"]
    return {"experiments": rows, "current": {
        "bundle": engine.name, "confusion": t.get("closed_set_classifier_only", {}).get("confusion_matrix"),
        "per_class": t.get("closed_set_classifier_only", {}).get("per_class"),
        "verdicts_by_label": t["hybrid_verdicts_by_true_label"], "lofo": t["lofo"], "benign": t["benign"],
        "conformal": t.get("conformal"), "rare": t.get("rare_families_excluded_from_known_set"),
        "novel_types": t.get("attack_types_absent_from_training_file"), "correlation": t["correlation"],
        "leakage": {"checks": m["leakage_audit"]["checks"], "limitations": m["leakage_audit"].get("limitations"),
                    "overlap": m["leakage_audit"]["feature_vector_overlap"]},
        "performance": m["performance"]}}


@app.get("/api/stream")
async def stream(since: int = 0):
    async def gen():
        last = since
        while True:
            new = engine.since(last)
            if new:
                last = new[-1]["id"]
            yield f"data: {json.dumps({'events': new, 'state': engine.state()}, allow_nan=False)}\n\n"
            await asyncio.sleep(1.0)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@app.get("/vendor/plotly.min.js")
def plotly_js():
    return FileResponse(Path(plotly.__file__).parent / "package_data" / "plotly.min.js", media_type="text/javascript")


@app.middleware("http")
async def no_stale_ui(request, call_next):
    resp = await call_next(request)
    if not request.url.path.startswith("/api"):
        resp.headers["Cache-Control"] = "no-cache"  # browsers revalidate, so UI changes show after a refresh
    return resp


app.mount("/", StaticFiles(directory=WEB, html=True), name="web")

if __name__ == "__main__":
    threading.Thread(target=worker, daemon=True).start()
    print(f"Console: http://127.0.0.1:{os.environ.get('PORT', 8000)}   (offline dataset replay / simulation only)")
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", 8000)), log_level="warning")
