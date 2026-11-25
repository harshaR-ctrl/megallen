"""Live inbox: inject.py appends flow events as JSON lines; the dashboard tails and scores them.

Events are dataset feature records (simulation), never packets or real traffic.
"""
import json
import time
import uuid

import numpy as np
import pandas as pd

from .pipeline import ROOT

INBOX = ROOT / "live" / "inbox.jsonl"


def write_event(features, dataset, scenario, source_ip, path=None, experiment=None):
    path = path or INBOX  # resolved at call time so tests/tools can redirect the inbox
    path.parent.mkdir(exist_ok=True)
    clean = {k: (None if isinstance(v, float) and not np.isfinite(v) else v.item() if hasattr(v, "item") else v)
             for k, v in features.items()}
    event = {"event_id": uuid.uuid4().hex[:12], "dataset": dataset, "experiment": experiment, "scenario": scenario,
             "meta": {"source_ip": source_ip, "timestamp": pd.Timestamp.now().isoformat(), "session": "live"},
             "features": clean}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, allow_nan=False) + "\n")
    return event


def read_new(offset, path=None):
    """Return (events, new_offset). Only complete lines are consumed; unparseable lines become error events."""
    path = path or INBOX
    if not path.exists():
        return [], 0
    if path.stat().st_size < offset:  # inbox was cleared
        offset = 0
    with open(path, "rb") as f:
        f.seek(offset)
        chunk = f.read()
    end = chunk.rfind(b"\n") + 1
    events = []
    for line in chunk[:end].splitlines():
        try:
            ev = json.loads(line)
            assert isinstance(ev.get("features"), dict)
        except (ValueError, AssertionError):
            ev = {"event_id": uuid.uuid4().hex[:12], "scenario": "malformed", "features": {}, "meta": {},
                  "parse_error": True}
        events.append(ev)
    return events, offset + end


def to_frames(events, schema):
    """Build (X, meta) for infer(). Events whose feature names or types do not match the schema are not
    repaired: they are returned in `bad` so infer() scores them alone and they come out PROCESSING_ERROR."""
    feats, numeric = schema["features"], set(schema["numeric"])
    good, bad = [], []
    for ev in events:
        f = ev["features"]
        ok = set(f) == set(feats) and all(
            (v is None or (isinstance(v, (int, float)) and not isinstance(v, bool))) if c in numeric
            else (v is None or isinstance(v, str)) for c, v in f.items())
        (good if ok else bad).append(ev)
    frames = []
    for group, valid in [(good, True), (bad, False)]:
        if not group:
            continue
        X = pd.DataFrame([e["features"] for e in group], index=[e["event_id"] for e in group])
        if valid:
            X = X[feats].astype({c: float for c in numeric})
        meta = pd.DataFrame([e.get("meta", {}) for e in group], index=X.index)
        meta["timestamp"] = pd.to_datetime(meta.get("timestamp"), errors="coerce")
        meta["scenario"] = [e.get("scenario") for e in group]
        meta["received"] = pd.Timestamp.now()
        frames.append((X, meta))
    return frames


def score(bundle, events):
    from .pipeline import infer
    out = []
    for X, meta in to_frames(events, bundle["feature_schema"]):
        out.append((infer(bundle, X, meta), meta))
    if not out:
        return None, None
    return pd.concat([r for r, _ in out]), pd.concat([m for _, m in out])


def stream(rows, dataset, scenario, source_ip, rate, path=None, experiment=None):
    """Send one block of rows that share a scenario name and source host."""
    stream_items([(row, scenario, source_ip) for _, row in rows.iterrows()], dataset, rate, path, experiment)


def stream_items(items, dataset, rate, path=None, experiment=None):
    """Send (row, scenario, source) items in order, `rate` per second (0 = as fast as possible)."""
    for i, (row, scenario, source_ip) in enumerate(items):
        write_event(row.to_dict(), dataset, scenario, source_ip, path, experiment)
        if rate:
            time.sleep(1 / rate)
        try:  # progress only; a closed or redirected console must not stop the send
            print(f"\rsent {i + 1}/{len(items)}  {scenario[:60]:<60}", end="", flush=True)
        except OSError:
            pass
    try:
        print()
    except OSError:
        pass


SCENARIOS = ["normal", "zero-day", "attack", "mix", "known", "synthetic", "malformed", "benign"]
STATUS_TEXT = {"hidden": "hidden from training", "rare": "rare family, never trained",
               "new": "new type, not in the training data", "known": "known to the model"}


def attack_status(schema, family, attack_type, novel_types=()):
    """What an attack type is to this model: hidden (zero-day), rare (never trained), new, or known."""
    if family == schema["holdout_family"]:
        return "hidden"
    if family not in schema["classes"]:
        return "rare"
    return "new" if attack_type in novel_types else "known"


def attack_catalog(schema, records, novel_types=()):
    """Every attack type in this bundle's test partition, with its family, count and status."""
    from .data import BENIGN
    t = records["truth"]
    sizes = t[t["label"] != BENIGN].groupby(["label", "label_raw"]).size()
    out = [{"type": raw, "family": fam, "count": int(n), "status": attack_status(schema, fam, raw, novel_types)}
           for (fam, raw), n in sizes.items()]
    return sorted(out, key=lambda r: (r["family"], -r["count"]))


def _select(records, mask, count, rng):
    pool = records["X"][mask.to_numpy()]
    if pool.empty:
        return pool, records["truth"].iloc[0:0]
    idx = rng.choice(len(pool), size=min(count, len(pool)), replace=False)
    rows = pool.iloc[idx].copy()
    return rows, records["truth"].loc[rows.index]


def plan_items(schema, records, scenario, count, rng, attack=None, novel_types=(), mix=(0.7, 0.15, 0.15)):
    """Build (row, scenario name, source host) items to inject.

    normal   - normal traffic from the test data
    zero-day - attacks from the family this model never saw in training
    attack   - one specific attack type (e.g. neptune) or a whole family (e.g. DoS); `attack` required
    known    - random attacks from families the model was trained on
    mix      - normal + zero-day + attack shuffled together (shares in `mix`); attack defaults to any known type
    synthetic, malformed - stress tests (out-of-range values; a record that must fail validation)
    """
    from .data import BENIGN
    t = records["truth"]
    holdout = schema["holdout_family"]

    def named(rows, truth, kind, source):
        items = []
        for (_, row), (fam, raw) in zip(rows.iterrows(), zip(truth["label"], truth["label_raw"])):
            if kind == "normal":
                name = "normal traffic"
            elif kind == "synthetic":
                name = "synthetic unusual traffic"
            else:
                st = attack_status(schema, fam, raw, novel_types)
                name = f"{'zero-day' if kind == 'zero-day' else 'attack'}: {raw} ({fam}, {STATUS_TEXT[st]})"
            items.append((row, name, source))
        return items

    if scenario == "malformed":
        bad = records["X"].iloc[[0]].copy().drop(columns=records["X"].columns[0])  # missing a required feature
        bad[schema["numeric"][1]] = "not-a-number"
        return [(bad.iloc[0], "malformed record", "sim-broken-1")]
    if scenario in ("normal", "benign"):
        return named(*_select(records, t["label"].eq(BENIGN), count, rng), "normal", "sim-host-ok")
    if scenario == "zero-day":
        items = named(*_select(records, t["label"].eq(holdout), count, rng), "zero-day", "sim-attacker-1")
        if not items:
            raise ValueError(f"no {holdout} records in this bundle's test data")
        return items
    if scenario == "known":
        return named(*_select(records, t["label"].isin(schema["classes"]) & t["label"].ne(BENIGN), count, rng),
                     "attack", "sim-attacker-2")
    if scenario == "attack":
        if not attack:
            raise ValueError("choose an attack type or family, e.g. neptune or DoS (python inject.py list)")
        a = attack.lower()
        mask = t["label_raw"].str.lower().eq(a) | t["label"].str.lower().eq(a)
        if not mask.any():
            raise ValueError(f"unknown attack '{attack}' (python inject.py list shows the options)")
        return named(*_select(records, mask, count, rng), "attack", "sim-attacker-2")
    if scenario == "synthetic":
        rows, truth = _select(records, t["label"].eq(BENIGN), count, rng)
        cols = list(rng.choice(schema["numeric"], size=min(12, len(schema["numeric"])), replace=False))
        rows[cols] = rows[cols].fillna(0) * rng.uniform(20, 200, size=(len(rows), len(cols))) + 1000
        return named(rows, truth, "synthetic", "sim-attacker-3")  # 12+ extreme columns needed to isolate a flow
    if scenario == "mix":
        n_zd, n_at = round(count * mix[1]), round(count * mix[2])
        items = (plan_items(schema, records, "normal", count - n_zd - n_at, rng)
                 + (plan_items(schema, records, "zero-day", n_zd, rng, novel_types=novel_types) if n_zd else [])
                 + (plan_items(schema, records, "attack" if attack else "known", n_at, rng, attack, novel_types) if n_at else []))
        return [items[i] for i in rng.permutation(len(items))]
    raise ValueError(f"unknown scenario '{scenario}'")


def pick_rows(schema, records, scenario, count, rng, attack=None):
    """Backward-compatible wrapper: (rows DataFrame, first scenario name, source) for a single-kind scenario."""
    items = plan_items(schema, records, scenario, count, rng, attack)
    return pd.DataFrame([r for r, _, _ in items]), items[0][1], items[0][2]
