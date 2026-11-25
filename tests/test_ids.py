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


# ---------- live inbox ----------

def test_live_inbox_scores_valid_events_and_never_normalizes_bad_ones(trained, tmp_path):
    from ids import live
    df, info, part, bundle = trained
    inbox = tmp_path / "inbox.jsonl"
    rows = df.loc[part == "test", info["features"]].head(5)
    for _, r in rows.iterrows():
        live.write_event(r.to_dict(), "cic_ids2017", "test", "sim-1", inbox)
    bad = rows.iloc[0].to_dict()
    bad.pop(info["features"][0])
    live.write_event(bad, "cic_ids2017", "missing-feature", "sim-1", inbox)
    wrong_type = dict(rows.iloc[0].to_dict(), **{info["numeric"][0]: "x"})
    live.write_event(wrong_type, "cic_ids2017", "bad-type", "sim-1", inbox)
    with open(inbox, "a") as f:
        f.write("not json\n{\"partial")  # garbage line + an incomplete trailing line
    events, offset = live.read_new(0, inbox)
    assert len(events) == 8 and offset < inbox.stat().st_size  # incomplete line left for the next read
    res, meta = live.score(bundle, events)
    v = res["verdict"]
    assert len(res) == 8 and (v[meta["scenario"] != "test"] == ERROR).all()
    assert v[meta["scenario"] == "test"].ne(ERROR).all()
    assert live.read_new(offset, inbox)[0] == []


# ---------- console API ----------

@pytest.mark.skipif(not list(pipeline.ARTIFACTS.glob("*/*/run_manifest.json")), reason="needs a trained bundle")
def test_console_api_fails_safe_and_validates_input(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from ids import live
    monkeypatch.setattr(live, "INBOX", tmp_path / "inbox.jsonl")
    import server
    monkeypatch.setattr(server, "FEEDBACK", tmp_path / "feedback.jsonl")
    server.engine.load(server.engine.name)
    c = TestClient(server.app)
    rows, name, src = live.pick_rows(server.engine.schema, server.engine.records, "malformed", 1, np.random.default_rng(0))
    live.stream(rows, server.engine.schema["dataset"], name, src, 0, path=live.INBOX)
    zd, name, src = live.pick_rows(server.engine.schema, server.engine.records, "zero-day", 5, np.random.default_rng(0))
    live.stream(zd, server.engine.schema["dataset"], name, src, 0, path=live.INBOX)
    server.engine.tick(0.1)
    ev = c.get("/api/events?source=live").json()
    assert len(ev) == 6 and NORMAL not in {e["verdict"] for e in ev}
    err = [e for e in ev if e["verdict"] == ERROR]
    assert len(err) == 1 and c.get(f"/api/events/{err[0]['id']}/explain").json()["shap"]["method"] == "unavailable"
    eid = ev[0]["id"]
    assert c.post(f"/api/events/{eid}/triage", json={"status": "escalated"}).json()["status"] == "escalated"
    assert (tmp_path / "feedback.jsonl").read_text().count("escalated") == 1
    assert c.post(f"/api/events/{eid}/triage", json={"status": "delete"}).status_code == 422
    assert c.post("/api/inject", json={"scenario": "../etc", "count": 1}).status_code == 422
    assert c.post("/api/inject", json={"scenario": "zero-day", "count": 10_000}).status_code == 422
    assert c.post("/api/bundle", json={"bundle": "../../secrets"}).status_code == 404
    assert c.get("/api/events/999999").status_code == 404


# ---------- explainable AI layer ----------

def test_glossary_describes_known_and_unknown_features():
    from ids import glossary
    assert glossary.describe("srv_serror_rate") == glossary.NSL["srv_serror_rate"]
    d = glossary.describe("fwd_iat_mean")
    assert d and "_" not in d


def _ev(verdict, novelty, cset, **kw):
    return {"verdict": verdict, "novelty": novelty, "set": cset, "score": kw.get("score", 0.1), "candidate": kw.get("candidate"),
            "conflict": kw.get("conflict", False), "error": kw.get("error")}


_needs_bundle = pytest.mark.skipif(not list(pipeline.ARTIFACTS.glob("*/*/run_manifest.json")), reason="needs a trained bundle")


@_needs_bundle
@pytest.mark.parametrize("ev,row", [
    (_ev(KNOWN, False, ["DoS"], candidate="DoS"), 1),
    (_ev(KNOWN, True, ["DoS"], candidate="DoS", conflict=True), 2),
    (_ev(NORMAL, False, ["BENIGN"]), 3),
    (_ev(UNKNOWN, True, ["BENIGN"]), 4),
    (_ev(UNKNOWN, True, []), 5),
    (_ev(UNKNOWN, True, ["BENIGN", "DoS"]), 5),
    (_ev(UNCERTAIN, False, []), 6),
    (_ev(UNCERTAIN, False, ["BENIGN", "DoS"]), 6),
    (_ev(ERROR, None, None, error="schema mismatch"), 7),
    (_ev(DEGRADED, None, None), 7),
])
def test_rule_for_matches_decision_table(ev, row):
    import server
    assert server.rule_for(ev) == row


@_needs_bundle
def test_summary_is_a_plain_sentence_for_every_verdict():
    import server
    scores = {"BENIGN": 0.6, "DoS": 0.3, "R2L": 0.1}
    cases = [_ev(UNKNOWN, True, []), _ev(KNOWN, False, ["DoS"], candidate="DoS"),
             _ev(KNOWN, True, ["DoS"], candidate="DoS", conflict=True), _ev(NORMAL, False, ["BENIGN"], score=-0.1),
             _ev(UNCERTAIN, False, ["BENIGN", "DoS"], score=-0.1), _ev(ERROR, None, None, error="schema mismatch"),
             _ev(DEGRADED, None, None)]
    for e in cases:
        s = server.summary(e, scores, 0.075)
        assert s.endswith(".") and "nan" not in s.lower() and "None" not in s
        if e["verdict"] in (UNKNOWN, KNOWN, NORMAL, UNCERTAIN):
            assert "alert line" in s
        if e["verdict"] == ERROR:
            assert "schema mismatch" in s


@pytest.fixture
def console(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from ids import live
    monkeypatch.setattr(live, "INBOX", tmp_path / "inbox.jsonl")
    import server
    monkeypatch.setattr(server, "FEEDBACK", tmp_path / "feedback.jsonl")
    server.engine.load(server.engine.name)
    server.engine.running = True
    server.engine.rate = 1000
    server.engine.tick(1.0)
    rows, name, src = live.pick_rows(server.engine.schema, server.engine.records, "malformed", 1, np.random.default_rng(0))
    live.stream(rows, server.engine.schema["dataset"], name, src, 0)
    server.engine.running = False
    server.engine.tick(0.1)
    return server, TestClient(server.app)


@_needs_bundle
def test_event_detail_pass_marks_match_conformal_sets(console):
    server, c = console
    ev = [e for e in c.get("/api/events?limit=2000").json() if e["verdict"] != ERROR]
    assert len(ev) > 100
    for e in ev[:300]:
        d = c.get(f"/api/events/{e['id']}").json()
        assert d["summary"] and 1 <= d["rule"] <= 7
        assert set(d["pass_marks"]) == set(server.engine.schema["classes"])
        assert all(0 <= v <= 1 for v in d["pass_marks"].values())
        fits = {k for k, p in d["scores"].items() if p is not None and p >= d["pass_marks"][k] - 1e-9}
        assert fits == set(d["event"]["set"] or []), (e["id"], d["scores"], d["pass_marks"], d["event"]["set"])


@_needs_bundle
def test_explain_describes_features_and_refuses_bad_records(console):
    server, c = console
    ev = c.get("/api/events?limit=2000").json()
    ok = next(e for e in ev if e["verdict"] == UNKNOWN)
    x = c.get(f"/api/events/{ok['id']}/explain").json()
    assert x["shap"]["top_features"] and all(t["description"] for t in x["shap"]["top_features"])
    assert x["baseline_deviation"] and all(d["description"] for d in x["baseline_deviation"])
    bad = next(e for e in ev if e["verdict"] == ERROR)
    assert c.get(f"/api/events/{bad['id']}/explain").json()["shap"]["method"] == "unavailable"


@_needs_bundle
def test_model_endpoint_explains_the_model(console):
    server, c = console
    m = c.get("/api/model").json()
    imp = [t["importance"] for t in m["importance"]]
    assert 0 < len(imp) <= 15 and imp == sorted(imp, reverse=True)
    assert all(t["description"] for t in m["importance"])
    assert all(0 <= v["pass_mark"] <= 1 for v in m["classes_cal"].values())
    assert "threshold" in m and m["target_fpr"] > 0
    assert m["holdout"] == server.engine.schema["holdout_family"]


# ---------- injection modes ----------

def test_injection_modes_pick_what_was_asked(trained):
    from ids import live
    df, info, part, bundle = trained
    test = df[part == "test"]
    records = {"X": test[info["features"]], "truth": test[["label", "label_raw"]]}
    schema = bundle["feature_schema"]
    rng = np.random.default_rng(0)
    truth = lambda items: records["truth"].loc[[r.name for r, _, _ in items]]  # noqa: E731
    assert set(truth(live.plan_items(schema, records, "normal", 20, rng))["label"]) == {"BENIGN"}
    assert set(truth(live.plan_items(schema, records, "zero-day", 20, rng))["label"]) == {schema["holdout_family"]}
    one = live.plan_items(schema, records, "attack", 10, rng, "DoS Hulk")
    assert set(truth(one)["label_raw"]) == {"DoS Hulk"} and one[0][1].startswith("attack: DoS Hulk (DoS, known")
    assert set(truth(live.plan_items(schema, records, "attack", 10, rng, "dos"))["label"]) == {"DoS"}  # family, any case
    mix = live.plan_items(schema, records, "mix", 40, rng, "Bot", mix=(0.5, 0.25, 0.25))
    t = truth(mix)
    assert len(mix) == 40 and (t["label"] == "BENIGN").sum() == 20 and (t["label"] == "PortScan").sum() == 10 and (t["label"] == "Bot").sum() == 10
    with pytest.raises(ValueError, match="unknown attack"):
        live.plan_items(schema, records, "attack", 5, rng, "nosuch")
    with pytest.raises(ValueError, match="choose an attack"):
        live.plan_items(schema, records, "attack", 5, rng)
    cat = {r["type"]: r["status"] for r in live.attack_catalog(schema, records)}
    assert cat["PortScan"] == "hidden" and cat["DoS Hulk"] == "known"


@pytest.mark.skipif(not list(pipeline.ARTIFACTS.glob("*/*/run_manifest.json")), reason="needs a trained bundle")
def test_inject_api_specific_attack_and_mix(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from ids import live
    monkeypatch.setattr(live, "INBOX", tmp_path / "inbox.jsonl")
    import server
    c = TestClient(server.app)
    types = c.get("/api/attack-types").json()["types"]
    assert types and {"type", "family", "count", "status"} <= set(types[0])
    known = next(t["type"] for t in types if t["status"] == "known")
    r = c.post("/api/inject", json={"scenario": "attack", "attack": known, "count": 5, "rate": 0}).json()
    assert r["queued"] == 5
    r = c.post("/api/inject", json={"scenario": "mix", "attack": known, "count": 20, "rate": 0}).json()
    assert r["queued"] == 20 and r["breakdown"].get("normal traffic") == 14
    assert c.post("/api/inject", json={"scenario": "attack", "attack": "nosuch", "count": 5}).status_code == 400
    assert c.post("/api/inject", json={"scenario": "attack", "attack": "../x", "count": 5}).status_code == 422
    assert c.post("/api/inject", json={"scenario": "mix", "count": 5, "zero_day_share": 0.8, "attack_share": 0.5}).status_code == 422
