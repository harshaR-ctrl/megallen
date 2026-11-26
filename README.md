# Megallen: leakage-audited open-world intrusion detection

Offline defensive research demonstrator: a class-weighted histogram gradient-boosting classifier (known attacks), a benign-only
Isolation Forest (novelty gate), class-conditional split conformal sets (uncertainty), and a deterministic
decision table, with temporal grouping, a heuristic triage priority, TreeSHAP/baseline explanations, PSI drift
and a real-time analyst console (FastAPI + plain JS + Plotly). Design specs: `architecture (1).md`, `pipeline (1).md`, `techstack (1).md`, `workflow (1).md`.

**Scope:** replays labelled public-dataset records offline. It is not a live sensor and does not establish
real-world zero-day detection.

## Layout

| Path | What |
|---|---|
| `ids/data.py` | Separate CIC-IDS2017 / NSL-KDD loaders, cleaning, quarantine, leakage audit, split manifests |
| `ids/core.py` | Finite-sample threshold, conformal sets, decision table, priority, correlation, PSI |
| `ids/pipeline.py` | Training, schema-validated inference, output contract, explanations, evaluation, bundles |
| `run.py` | One experiment end to end -> `artifacts/<dataset>/<experiment_id>/` |
| `server.py` | Console backend: detection engine (replay + live inbox), REST API, server-sent event stream |
| `web/` | Console frontend: Live monitor, Alerts, How it decides, Model results. Plain JS + Plotly, no build step |
| `ids/glossary.py` | Plain-English description of every feature, used to write explanations as sentences |
| `inject.py`, `ids/live.py` | Injection into the live inbox: normal, zero-day, a specific attack type or family, a shuffled mix, plus stress tests |
| `tests/test_ids.py` | Checklist tests (decision table, fail-safes, calibration, splits, leakage, bundle integrity, console API, explanations) |
| `data/raw/<dataset>/` | Raw files, kept read-only and unmodified (git-ignored) |
| `feedback/feedback_log.jsonl` | Append-only analyst feedback; never used for training |

## Setup

```bash
python -m venv .venv && .venv\Scripts\activate      # Windows
pip install -r requirements.txt
python -m pytest tests -q
```

## Data

- **NSL-KDD:** put `KDDTrain+.txt` and `KDDTest+.txt` in `data/raw/nsl_kdd/` (41 features + label + difficulty).
  The official test file stays the test partition; train/validation/anom_cal/conf_cal come from the training file only.
- **CIC-IDS2017:** put the labelled flow CSVs (`MachineLearningCVE` or `TrafficLabelling`) in `data/raw/cic_ids2017/`.
  Files whose schema differs from the first file are quarantined, not patched. IPs, ports (except Destination
  Port), Flow ID and timestamps are metadata only. Temporal correlation needs the `TrafficLabelling` version (it has IP and time columns).

Label maps: `NSL_FAMILY` and `CIC_FAMILY` in `ids/data.py`. Unknown labels become `UNMAPPED` and are quarantined, never benign.

## Run experiments

```bash
python run.py nsl_kdd --holdout Probe
python run.py nsl_kdd --holdout DoS
python run.py nsl_kdd --holdout R2L
python run.py nsl_kdd --holdout Probe --split random                      # split-optimism audit
python run.py cic_ids2017 --holdout PortScan --max-rows-per-class 50000   # start with a sample
python run.py cic_ids2017 --holdout PortScan --max-rows-per-class 50000 --no-port
python server.py                 # console at http://127.0.0.1:8000
```

Defaults: seed 42, conformal alpha 0.05, target benign FPR 0.01, 200 trees. All arguments, file hashes,
versions and the git commit go into `run_manifest.json`.

## Console: detect a simulated zero-day live

```bash
# terminal 1
python server.py                  # open http://127.0.0.1:8000

# terminal 2 (or use the Simulate panel in the console)
python inject.py                  # endless random stream (normal + zero-days + random attacks); prints the
                                  #   dashboard's verdict next to each flow. Ctrl+C stops, --count N limits
python inject.py list             # every attack type you can send and what it is to this model
python inject.py normal           # normal traffic
python inject.py zero-day         # the attack family this model never saw (Probe for lofo-probe-grouped)
python inject.py attack neptune   # one specific attack type (or a family: attack DoS)
python inject.py mix --attack smurf   # 70% normal + 15% zero-day + 15% smurf, shuffled
python inject.py synthetic        # normal flows with 12 features pushed far out of range
python inject.py malformed        # broken record: must show "Bad record", never Normal
python inject.py zero-day --count 100 --rate 20 --experiment nsl_kdd/lofo-dos-grouped
python inject.py clear            # empty the inbox
```

The console has four views:

- **Live monitor:** a getting-started strip (start the replay, send a zero-day, open the newest alert), counters
  for flows checked and each verdict, a chart of how unusual each flow is against the red alert line, verdicts over
  time, a list of possible zero-days (only the ones you sent, or all), the Simulate panel, traffic shift (drift)
  and your review queue. Every number has a "?" tooltip. Space starts or pauses the replay.
- **Alerts:** filter by verdict, source (sent by you or test replay), review status and text. Selecting an alert
  opens **"Why it decided this"** straight away (see Explainable AI below), then the suggested next step and your
  review: Not reviewed, Investigating, Escalated, Resolved or False alarm, with a note (keys: `j`/`k` move,
  `i` investigating, `e` escalate, `r` resolved, `f` false alarm). Every review is appended to
  `feedback/feedback_log.jsonl` and never changes a model or threshold.
- **How it decides:** the pipeline from input check to verdict, the decision rules in order, the confidence bar of
  every attack class, the features the classifier relies on most, and a glossary of the words the console uses.
- **Model results:** every trained model on its untouched test data side by side (click one to use it), plus which
  class the classifier guessed, the final verdict by true traffic type, the leakage checks and the speed.

The server binds to 127.0.0.1 only. Inject requests are validated (scenario enum, count 1-500), all event text
is rendered with `textContent`, and bundles load only from `artifacts/` after checksum verification. Make sure the
injector's `--experiment` matches the console's model so "zero-day" means a family that model never saw. This is a
simulation: no packets are sent and nothing is scanned. A zero-day here is a held-out dataset family, not a
real-world zero-day.

## Explainable AI

Every alert explains itself in three steps that mirror how the verdict was actually made, so the explanation is
the decision, not a story told after it:

1. **Is the traffic unusual?** The flow's unusualness score from the Isolation Forest (trained only on normal
   traffic) is drawn against the alert line. The line is the finite-sample threshold set on held-back normal
   traffic so about 1% of normal flows cross it.
2. **Does it match a known attack?** Each class's classifier score is drawn against that class's confidence bar.
   The bars come from class-conditional conformal calibration (bar = 1 - q_c). A class "fits" only if its score
   reaches its bar, and the fitting classes are exactly the conformal set the decision used (a test checks this).
3. **Which rule fired?** The decision table is shown with the matching row highlighted (`rule_for` in `server.py`).

Above the steps, one plain-English sentence sums it up, for example: "Flagged as a possible zero-day: its
unusualness score 0.180 is above the alert line 0.075, and no known class fit it with enough confidence. The
classifier's best guess was DoS (68%), which is not enough to name a known attack."

Below the steps:

- **What made it unusual:** the features furthest from the benign training baseline (median and 95th percentile),
  written as sentences. This is a diagnostic comparison, not SHAP and not proof of cause.
- **What the classifier relied on:** TreeSHAP values of the gradient-boosting classifier for its candidate or top class,
  pushing towards or away from it. SHAP explains the classifier only; the Isolation Forest is explained by the
  baseline deviation above.
- **Global view:** the "How it decides" page shows the classifier's top 15 features by mean |SHAP|.

`ids/glossary.py` gives every NSL-KDD feature (and common CIC-IDS2017 ones) a plain description; other names fall
back to readable words. The API behind this: `/api/events/{id}` (summary, rule, scores, confidence bars),
`/api/events/{id}/explain` (SHAP and baseline deviation with descriptions) and `/api/model` (importances, bars,
alert line).

## Design decisions worth knowing

- **Rare families leave the known label set.** A family with fewer than 3 x 19 distinct training vectors cannot give
  `conf_cal` the 19 rows a finite quantile needs at alpha = 0.05. Its include-always fallback would then sit in every
  conformal set and block every `NORMAL` verdict. Such families (NSL-KDD: U2R; CIC: Heartbleed, Infiltration) are
  trained on no model and are evaluated in test as unseen families. Small calibratable families get at least 19 `conf_cal` rows.
- **Grouping key:** identical feature vectors never cross partitions. CIC day/file-aware splitting is infeasible
  because attack families are confined to single capture days; no temporal-generalisation claim is made.
- **Priority weights** (0.45/0.30/0.10/0.15) are provisional placeholders, not tuned. Display bands are validation
  quantiles (50/80/95%). A missing component is dropped and the remaining weights renormalised, never zero-filled.
- **Wilson 95% intervals** assume independent rows; session dependence makes them optimistic.
- **Bundles** are written atomically with SHA-256 checksums and load only from `artifacts/` after verification
  (joblib can execute code; never load uploaded model files).
