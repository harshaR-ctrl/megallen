"""Inject simulated traffic into the live console (run in a second terminal).

SIMULATION ONLY: writes stored dataset records to live/inbox.jsonl. No packets are sent, nothing is scanned.

  python inject.py                            # endless random stream: normal + zero-days + random attacks,
                                              #   with the dashboard's verdict printed next to each flow (Ctrl+C stops)
  python inject.py --count 100 --rate 5       # same, but stop after 100 flows; 5 flows per second
  python inject.py list                       # every attack type you can send, and what it is to the model
  python inject.py normal                     # normal traffic
  python inject.py zero-day                   # attacks from the family this model never saw in training
  python inject.py attack neptune             # one specific attack type
  python inject.py attack DoS                 # any attack from one family
  python inject.py mix --attack smurf         # 70% normal + 15% zero-day + 15% smurf, shuffled
  python inject.py synthetic                  # normal flows pushed far out of range
  python inject.py malformed                  # a broken record: must show "Bad record", never Normal
  python inject.py clear                      # empty the inbox
Options: --count  --rate (flows per second)  --experiment nsl_kdd/lofo-dos-grouped  --console http://127.0.0.1:8000
"""
import argparse
import json
import time
import urllib.parse
import urllib.request
from collections import Counter

import joblib
import numpy as np

from ids import live, pipeline

PLAIN = {"UNKNOWN_ANOMALY": "Possible zero-day", "KNOWN_ATTACK": "Known attack", "UNCERTAIN_REVIEW": "Unclear",
         "DEGRADED_REVIEW": "Model problem", "PROCESSING_ERROR": "Bad record", "NORMAL": "Normal"}


def get_json(url, timeout=2):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except (OSError, ValueError):
        return None


def console_model(url):
    """The model the running console has loaded, so 'zero-day' means the same thing on both sides."""
    return (get_json(f"{url}/api/state") or {}).get("bundle")


def expected(kind, status):
    """The verdict a flow should get, or None when either outcome is reasonable (new or rare attack types)."""
    if kind == "normal":
        return "NORMAL"
    if kind == "zero-day" or status == "hidden":
        return "UNKNOWN_ANOMALY"
    return "KNOWN_ATTACK" if status == "known" else None


def say(text):
    try:
        print(text, flush=True)
    except OSError:  # closed or redirected console must not stop the stream
        pass


def run_stream(a, schema, records, novel):
    """Send random flows one by one and print what the dashboard decided for each, in order."""
    rng = np.random.default_rng(a.seed)
    gen = live.stream_random(schema, records, rng, (1 - a.zero_day_share - a.attack_share, a.zero_day_share, a.attack_share), novel)
    online = console_model(a.console) is not None
    say(f"SIMULATION: random stream for model {a.experiment} "
        f"(hidden from training: {schema['holdout_family']}), {a.rate:g} flows/s"
        + (f", {a.count} flows" if a.count else ", Ctrl+C to stop"))
    if not online:
        say(f"Console not reachable at {a.console}: flows still go to the inbox, but no verdicts can be shown.")
    say(f"\n{'#':>5}  {'sent':<52}  dashboard verdict")
    pending, sent, tally, matched, judged = [], 0, Counter(), 0, 0
    t_end_wait = None

    def report(force=False):
        nonlocal matched, judged
        if not pending:
            return
        got = (get_json(f"{a.console}/api/verdicts?refs=" + urllib.parse.quote(",".join(p[1] for p in pending))) or {}).get("verdicts", {}) if online else {}
        while pending:
            n, ref, label, exp, t0 = pending[0]
            v = got.get(ref)
            if v is None and not force and time.time() - t0 < 5:
                break  # keep output in order; wait for the console to score this one
            pending.pop(0)
            if v is None:
                say(f"{n:>5}  {label[:52]:<52}  (not scored yet)")
                continue
            tally[v["verdict"]] += 1
            note = ""
            if exp is not None:
                judged += 1
                ok = v["verdict"] == exp
                matched += ok
                note = "  as expected" if ok else f"  (expected {PLAIN[exp]})"
            cand = f": {v['candidate']}" if v.get("candidate") else ""
            say(f"{n:>5}  {label[:52]:<52}  {PLAIN[v['verdict']]}{cand}{note}")

    try:
        for kind, (row, scenario, source) in gen:
            ev = live.write_event(row.to_dict(), schema["dataset"], scenario, source, experiment=a.experiment)
            fam, raw = records["truth"].loc[row.name, ["label", "label_raw"]]
            status = None if kind == "normal" else live.attack_status(schema, fam, raw, novel)
            sent += 1
            pending.append((sent, ev["event_id"], scenario, expected(kind, status), time.time()))
            report()
            if a.count and sent >= a.count:
                break
            time.sleep(1 / a.rate if a.rate else 0)
        t_end_wait = time.time() + 6
        while pending and time.time() < t_end_wait:  # let the console score the last flows
            time.sleep(0.5)
            report()
        report(force=True)
    except KeyboardInterrupt:
        report(force=True)
    say(f"\nSent {sent} flows. Dashboard verdicts: " + (", ".join(f"{PLAIN[k]} {n}" for k, n in tally.most_common()) or "none received"))
    if judged:
        say(f"Matched the expected verdict for {matched} of {judged} flows with a clear expectation "
            f"({100 * matched / judged:.0f}%). New and rare attack types have no fixed expectation.")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", nargs="?", default="stream", choices=["stream"] + live.SCENARIOS + ["list", "clear"])
    ap.add_argument("attack", nargs="?", help="attack type or family for 'attack' (see: python inject.py list)")
    ap.add_argument("--attack", dest="attack_opt", help="attack type or family mixed in by 'mix'")
    ap.add_argument("--experiment", help="<dataset>/<experiment_id> under artifacts/ (default: the model the console is using)")
    ap.add_argument("--console", default="http://127.0.0.1:8000", help="console address, used to find its model and verdicts")
    ap.add_argument("--count", type=int, help="number of flows (stream default: endless; other modes: 40)")
    ap.add_argument("--rate", type=float, help="flows per second (stream default 15, other modes 5; 0 = instant)")
    ap.add_argument("--zero-day-share", type=float, default=0.15)
    ap.add_argument("--attack-share", type=float, help="share of other attacks (stream default 0.25, mix 0.15)")
    ap.add_argument("--seed", type=int)
    a = ap.parse_args(argv)

    if a.scenario == "clear":
        live.INBOX.unlink(missing_ok=True)
        return print(f"cleared {live.INBOX}")
    stream = a.scenario == "stream"
    a.rate = a.rate if a.rate is not None else (15 if stream else 5)
    a.attack_share = a.attack_share if a.attack_share is not None else (0.25 if stream else 0.15)
    if a.zero_day_share + a.attack_share > 1:
        raise SystemExit("--zero-day-share + --attack-share must be at most 1")
    a.experiment = a.experiment or console_model(a.console) or "nsl_kdd/lofo-probe-grouped"
    path = pipeline.ARTIFACTS / a.experiment
    bundle = pipeline.load_bundle(path)  # verifies checksums before reading test_records.joblib
    schema, records = bundle["feature_schema"], joblib.load(path / "test_records.joblib")
    novel = (bundle["metrics"]["test"].get("attack_types_absent_from_training_file") or {}).get("types", [])

    if a.scenario == "list":
        print(f"Model {a.experiment}: hidden from training = {schema['holdout_family']}\n")
        print(f"{'attack type':<18}{'family':<8}{'flows':>7}  what it is to this model")
        for r in live.attack_catalog(schema, records, novel):
            print(f"{r['type']:<18}{r['family']:<8}{r['count']:>7}  {live.STATUS_TEXT[r['status']]}")
        return
    if stream:
        return run_stream(a, schema, records, novel)
    try:
        items = live.plan_items(schema, records, a.scenario, a.count or 40, np.random.default_rng(a.seed),
                                a.attack or a.attack_opt, novel,
                                (1 - a.zero_day_share - a.attack_share, a.zero_day_share, a.attack_share))
    except ValueError as e:
        raise SystemExit(str(e))
    print(f"SIMULATION: sending {len(items)} flows ({a.scenario}{' ' + (a.attack or a.attack_opt) if a.attack or a.attack_opt else ''}) "
          f"to {live.INBOX} for {a.experiment}")
    live.stream_items(items, schema["dataset"], a.rate, experiment=a.experiment)


if __name__ == "__main__":
    main()
