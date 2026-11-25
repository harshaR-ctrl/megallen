"""Inject simulated traffic into the live console (run in a second terminal).

SIMULATION ONLY: writes stored dataset records to live/inbox.jsonl. No packets are sent, nothing is scanned.

  python inject.py list                       # every attack type you can send, and what it is to the model
  python inject.py normal                     # normal traffic
  python inject.py zero-day                   # attacks from the family this model never saw in training
  python inject.py attack neptune             # one specific attack type
  python inject.py attack DoS                 # any attack from one family
  python inject.py mix --attack smurf         # 70% normal + 15% zero-day + 15% smurf, shuffled
  python inject.py mix --zero-day-share 0.3 --attack-share 0.1 --count 200
  python inject.py synthetic                  # normal flows pushed far out of range
  python inject.py malformed                  # a broken record: must show "Bad record", never Normal
  python inject.py clear                      # empty the inbox
Common options: --count 40  --rate 5 (flows per second, 0 = instant)  --experiment nsl_kdd/lofo-dos-grouped
"""
import argparse
import json
import urllib.request

import joblib
import numpy as np

from ids import live, pipeline


def console_model(url):
    """The model the running console has loaded, so 'zero-day' means the same thing on both sides."""
    try:
        with urllib.request.urlopen(f"{url}/api/state", timeout=2) as r:
            return json.load(r)["bundle"]
    except (OSError, ValueError, KeyError):
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", choices=live.SCENARIOS + ["list", "clear"])
    ap.add_argument("attack", nargs="?", help="attack type or family for 'attack' (see: python inject.py list)")
    ap.add_argument("--attack", dest="attack_opt", help="attack type or family mixed in by 'mix'")
    ap.add_argument("--experiment", help="<dataset>/<experiment_id> under artifacts/ (default: the model the console is using)")
    ap.add_argument("--console", default="http://127.0.0.1:8000", help="console address, used to find its current model")
    ap.add_argument("--count", type=int, default=40)
    ap.add_argument("--rate", type=float, default=5, help="flows per second (0 = as fast as possible)")
    ap.add_argument("--zero-day-share", type=float, default=0.15)
    ap.add_argument("--attack-share", type=float, default=0.15)
    ap.add_argument("--seed", type=int)
    a = ap.parse_args(argv)

    if a.scenario == "clear":
        live.INBOX.unlink(missing_ok=True)
        return print(f"cleared {live.INBOX}")
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
    if a.zero_day_share + a.attack_share > 1:
        raise SystemExit("--zero-day-share + --attack-share must be at most 1")
    try:
        items = live.plan_items(schema, records, a.scenario, a.count, np.random.default_rng(a.seed),
                                a.attack or a.attack_opt, novel,
                                (1 - a.zero_day_share - a.attack_share, a.zero_day_share, a.attack_share))
    except ValueError as e:
        raise SystemExit(str(e))
    print(f"SIMULATION: sending {len(items)} flows ({a.scenario}{' ' + (a.attack or a.attack_opt) if a.attack or a.attack_opt else ''}) "
          f"to {live.INBOX} for {a.experiment}")
    live.stream_items(items, schema["dataset"], a.rate, experiment=a.experiment)


if __name__ == "__main__":
    main()
