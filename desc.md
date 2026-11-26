# Megallen: Architecture, Accuracy and Roadmap

This document describes how Megallen is built today, how accurate it is, what you need to know before demoing or
extending it, and what should come next. For a shorter pitch-style overview see `project description.md`; for
setup commands see `README.md`; for the console's screen layout see `layout.md`.

Everything numeric below was read from the committed `artifacts/nsl_kdd/*/metrics.json` files (2026-11-26), not
from the design specifications, which quote older targets.

---

## 1. What Megallen is

An **offline, open-world network intrusion detection system**. For every network connection it decides one of:

| Verdict | Meaning |
|---|---|
| **Possible zero-day** | Unlike normal traffic **and** unlike any attack the model was trained on |
| **Known attack** | Clearly matches exactly one trained attack type |
| **Unclear** | Not unusual, but the classifier can't settle on one class, so a person should look |
| **Normal** | Both models agree it looks normal |
| **Bad record** / **Model problem** | Input failed validation or a model was unavailable; **never** turned into Normal |

Every verdict comes with a plain-English explanation, and an analyst can review each alert in a web console.

> **It does not watch a real network.** All traffic is recorded data from the public NSL-KDD dataset (1998 DARPA /
> MIT Lincoln Lab lab network), either replayed or injected on demand. A "zero-day" here means an attack family that
> was **deliberately removed from training**, not a real-world unknown attack.

Two properties are deliberate and load-bearing:

- **Fail-safe:** a malformed record or a missing model can never become `NORMAL`. The decision table has an explicit
  degraded/error branch.
- **Leakage-audited:** identifiers (IPs, ports, timestamps, flow IDs, labels) are excluded from features, identical
  feature vectors are kept in one split, and every run records hashes, arguments, library versions and the git commit.

---

## 2. Current architecture

### 2.1 Big picture

```
 data/raw/nsl_kdd/            run.py (offline training, one CPU command)
 KDDTrain+.txt  ─────────────►  load → clean → leakage audit → 5-way split
 KDDTest+.txt                   → train gradient-boosting classifier + Isolation Forest
                                → calibrate alert line + confidence bars
                                → evaluate once on the untouched test file
                                → write checksummed bundle to artifacts/
                                                │
                                                ▼
 inject.py / "Send traffic" ──► live/inbox.jsonl ──┐
                                                   ▼
                              server.py  (FastAPI, 127.0.0.1 only)
                              ├─ Engine thread: replays the test set + tails the inbox,
                              │   scores every flow, groups bursts, computes drift
                              ├─ REST API + server-sent-event stream
                              └─ serves web/ (plain HTML/CSS/JS + Plotly)
                                                   │
                                                   ▼
                              Browser console: Live monitor · Alerts · How it decides · Model results
```

### 2.2 How one flow is scored

```
 flow ─► 1. Input check (41 features, right names, right types) ── fail ─► Bad record
          │
          ├─► 2a. Isolation Forest, trained on NORMAL traffic only
          │        score vs alert line (set so ~1% of normal flows cross it)  → "unusual?" yes/no
          │
          ├─► 2b. Gradient-boosting classifier over known classes (e.g. BENIGN, DoS, R2L)
          │        each class has its own confidence bar (conformal calibration)  → which classes "fit"
          │
          └─► 3. Seven fixed decision rules (first match wins) → verdict
                 4. Urgency score 0-100 (sorting aid only, never changes the verdict)
                 5. Burst grouping: 3+ alerts from one host within 30 s
                 6. Explanation (summary, 3-step path, feature deviations, SHAP)
```

The two models are independent: the Isolation Forest only answers "is this unlike benign traffic?", the classifier
only answers "which known class(es) fit?". Neither can overrule the decision table, and the classifier is never
trained on the hidden family.

### 2.3 The 7 decision rules

| # | Unusual? | Known classes that fit | Verdict |
|---|---|---|---|
| 1 | No | exactly one attack class | Known attack |
| 2 | Yes | exactly one attack class | Known attack + "possible new variant" warning |
| 3 | No | only normal | Normal |
| 4 | Yes | only normal | Possible zero-day |
| 5 | Yes | none, or several | Possible zero-day |
| 6 | No | none, or several | Unclear |
| 7 | any | broken input or failed model | Bad record / Model problem (never Normal) |

Implementation: `ids/core.py:decide()`. If either model is unavailable (`None` instead of a score/set) the flow is
`DEGRADED_REVIEW`, never `NORMAL`. The rule that fired is exposed per alert (`server.rule_for()`) and shown in the
console, so the explanation and the verdict cannot drift apart.

### 2.4 Training pipeline (`run.py`)

1. **Load** each dataset with its own loader (NSL-KDD and CIC-IDS2017 are never mixed). Raw files are hashed
   (SHA-256) and never modified.
2. **Clean:** convert types, turn infinities into missing values, and quarantine rows with unknown labels or
   contradictory labels for identical feature vectors. Nothing is ever silently relabelled "normal".
3. **Leakage guard:** IPs, ports, timestamps, flow IDs, labels and NSL's "difficulty" column are kept out of the features.
4. **Split into 5 disjoint parts:** train · validation · normal-only calibration (`anom_cal`) · conformal
   calibration (`conf_cal`) · test. Identical feature vectors always stay in the same part. NSL-KDD keeps its
   official test file as the test set; everything else comes from `KDDTrain+.txt`.
5. **Hide one attack family** (leave-one-family-out, "LOFO") from training, validation and calibration, so it can play
   the zero-day. Families too small to calibrate are also excluded and evaluated as unseen — the rule is fewer than
   `3 × min_calibration_rows(α)` distinct training vectors, i.e. **57 vectors** at α = 0.05.
6. **Train** a class-weighted `HistGradientBoostingClassifier` (200 iterations, seed 42, native categorical support)
   and an `IsolationForest` (200 trees, normal traffic only).
7. **Calibrate:**
   - Alert line: finite-sample rule `k = ⌈(n+1)(1−β)⌉` on **7,479** normal flows, β = 1%. Ties are not flagged;
     if `k > n` the threshold becomes "no trigger" rather than a made-up number.
   - Per-class confidence bars: class-conditional split conformal, α = 0.05, with a documented fallback when a class
     has too few calibration rows.
8. **Evaluate once** on the test set; write `metrics.json` (data quality, leakage audit, validation, test, verdict
   counts, per-class report, confusion matrix, conformal coverage, LOFO and rare-family results, correlation, PSI,
   performance, one example output record).
9. **Save a bundle** atomically with a checksum manifest (`run_manifest.json` records file hashes, arguments, library
   versions and the git commit). The console refuses to load a bundle whose files changed.

### 2.5 Trained models today

| Bundle | Hidden attack family | Purpose |
|---|---|---|
| `nsl_kdd/lofo-probe-grouped` | Probe | Main model (console default) |
| `nsl_kdd/lofo-dos-grouped` | DoS | Zero-day test with DoS unseen |
| `nsl_kdd/lofo-r2l-grouped` | R2L | Zero-day test with R2L unseen |
| `nsl_kdd/lofo-probe-random` | Probe | Leakage audit only (random instead of grouped split) |

Each bundle holds 2 ML models (classifier + Isolation Forest), so there are **8 trained models** in **4 bundles**
covering 3 distinct holdout setups. The random-split audit produces *identical* test metrics to the grouped Probe
bundle, which is the intended evidence that grouping by feature-vector fingerprint did not hide leakage. No
CIC-IDS2017 model exists yet because `data/raw/cic_ids2017/` is empty on this machine; the loader and port-ablation
switch are already implemented.

### 2.6 Code layout

| Path | Lines | Role |
|---|---|---|
| `ids/data.py` | 261 | Loaders, cleaning, quarantine, leakage audit, split, split manifest |
| `ids/core.py` | 171 | Calibration math, conformal sets, decision rules, urgency, burst grouping, drift (PSI) |
| `ids/pipeline.py` | 408 | Training, schema-checked inference, output record, explanations, evaluation, bundles |
| `ids/live.py` | 225 | Live inbox, attack catalogue, injection planning (normal / zero-day / specific attack / mix) |
| `ids/glossary.py` | 70 | Plain-English description of every feature |
| `run.py` | 100 | Train + evaluate one experiment |
| `inject.py` | 174 | Terminal tool to send simulated traffic and read back the console's verdicts |
| `server.py` | 483 | Detection engine thread + API + static file server |
| `web/` | 1,299 | Console: `index.html` 189, `style.css` 429, `app.js` 681 (no framework, no build step) |
| `tests/test_ids.py` | 470 | 47 test cases |
| `desc.md`, `layout.md`, `colour-palette.md`, `README.md` | — | Description, UI layout, design tokens, setup/usage |

### 2.7 API (`server.py`, localhost only)

FastAPI also serves interactive docs at `/api/docs`. The engine ticks every 0.4 s; the browser stream is pushed
once per second.

| Endpoint | Purpose |
|---|---|
| `GET /api/stream` | Server-sent events: new scored flows + full state, every second (`?since=<id>`) |
| `GET /api/state` | Counts, replay progress, drift, model in use, injection/model mismatch |
| `POST /api/replay` | `start` / `pause` / `reset`; `rate` 10–5,000 flows/s (default 200) |
| `POST /api/bundle` | Switch model bundle (unknown bundle → 404) |
| `GET /api/attack-types` | Every injectable attack type and what it is to this model |
| `POST /api/inject` | `normal` / `zero-day` / `attack` / `mix` / `known` / `synthetic` / `benign` / `malformed`; `count` 1–500, `rate` ≤ 200, zero-day/attack shares must sum to ≤ 1 |
| `GET /api/verdicts` | Dashboard verdicts for flows sent by `inject.py`, looked up by inbox event id |
| `GET /api/events` | Filtered alert list: `verdict`, `status`, `source`, text `q`, `limit` (capped at 2,000) |
| `GET /api/events/{id}` | One alert: summary sentence, rule fired, scores, confidence bars, output record |
| `GET /api/events/{id}/explain` | Feature deviations + TreeSHAP, in plain words |
| `POST /api/events/{id}/triage` | Record a review: `new` / `investigating` / `escalated` / `resolved` / `false_positive`, plus a note (≤ 500 chars), append-only audit log |
| `GET /api/model` | Alert line, confidence bars, top features (for "How it decides") |
| `GET /api/metrics` | Evaluation results of every bundle plus the current bundle's full detail |
| `GET /vendor/plotly.min.js` | Plotly served locally, so the console works offline |

Input is validated by Pydantic models (pattern-constrained scenario/status strings, bounded rates and counts).
Unknown or over-limit input returns 4xx rather than being coerced.

### 2.8 Explainable AI (where it lives)

| Layer | What the user sees | Source |
|---|---|---|
| Summary | One sentence per alert ("Flagged as a possible zero-day: its unusualness score 0.180 is above the alert line 0.075…") | `server.summary()` |
| Decision path | "Unlike normal traffic? Yes + Matches a known attack? No = Possible zero-day" | console |
| Step 1 | Gauge: score vs alert line | Isolation Forest + calibration |
| Step 2 | Each class's score vs its confidence bar ("fits" / "doesn't fit") | conformal calibration (unit-tested to match the real decision) |
| Step 3 | The rule that fired, out of 7 | `server.rule_for()` |
| Feature evidence | "Share of connections that failed to open is 0.86; normal is usually 0.00" | benign-baseline deviation (diagnostic, not causal) |
| Classifier evidence | Bars pushing towards or away from a class | TreeSHAP on the gradient-boosting classifier |
| Global view | Top 8 features the classifier relies on, rules, glossary | `/api/model` |

Explanations are computed **on request only** and are labelled separately from SHAP: baseline deviation is a
distance from benign medians (p05–p95 spread), not a causal or model-attribution claim. If `shap` is unavailable,
the response says so and the rest of the explanation still renders. The detail pane prints the measured explanation
time ("Explained in N ms").

### 2.9 Console

Four views, no page reload, no build step:

| View | What it is for |
|---|---|
| **Live monitor** | Getting-started actions, KPI counters, unusualness chart with the frozen alert line, verdict mix, zero-day feed, Simulate panel, traffic drift, review queue |
| **Alerts** | Filterable table (verdict, source, review status, free text) + "Why it decided this" detail pane |
| **How it decides** | Five-stage pipeline, the 7 rules, per-class confidence bars, top features, glossary |
| **Model results** | Every bundle side by side, confusion matrix, per-class report, LOFO/benign numbers, leakage audit, speed |

Behaviour that matters for a demo:

- **Hide IPs** is on by default and masks IPv4 addresses client-side to the first two octets; it never changes the
  data the server scored.
- **Replay** is test-set replay at a configurable rate; **Simulate** and `inject.py` write JSON lines to
  `live/inbox.jsonl`, which the engine tails.
- **Reviews** (Not reviewed / Investigating / Escalated / Resolved / False alarm) are appended to
  `feedback/feedback_log.jsonl`. They never retrain the model or change a threshold.
- **Keyboard:** `/` jumps to the alert search; `j` / `k` move down/up the alert list; `i` investigating,
  `e` escalate, `r` resolved, `f` false alarm. `Esc` closes the tooltip/dialog.
- The console keeps the newest **40,000** events in memory and re-correlates the last **3,000** rows per source on
  each update. Restarting the server clears events; only reviews persist.

### 2.10 Tech stack and repository state

Python 3.13 · pandas 2.3.0 · NumPy 2.3.4 · scikit-learn 1.7.2 · SHAP 0.51.0 · joblib 1.5.1 · FastAPI 0.119.0 ·
Uvicorn 0.37.0 · Plotly 6.5.0 (served from the installed package) · pytest 8.4.2 · plain HTML/CSS/JavaScript.

The working tree is clean and the current work (console, injection, explanations, docs) is committed. Data, model
bundles, the live inbox and feedback are git-ignored, so a clone has code and docs but no dataset or trained model.

---

## 3. Accuracy

All numbers come from each bundle's `metrics.json`. **Test = the official KDDTest+ file**: 22,544 flows, of which
**22,395 were scored**. The 149 missing rows were quarantined because their feature vector appears elsewhere with a
different label (see below). The test file was never used for training, tuning or calibration. Rates are point
estimates; `metrics.json` also stores Wilson 95% intervals.

Data quality, from `metrics.json`: both files load to **148,517 rows** (KDDTrain+ 125,973 + KDDTest+ 22,544).
**210 rows** are quarantined for contradictory labels on identical feature vectors; duplicated feature vectors
(727) and exact duplicate rows (629) are **counted and reported, not deleted**, because removing them would change
the official test distribution. No rows have unmapped labels.

### 3.1 Known-attack classifier

Closed-set performance over the classes this bundle was allowed to learn:

| Model | Known classes | Validation macro-F1 | **Test accuracy** | Test macro-F1 | Test balanced accuracy |
|---|---|---|---|---|---|
| Hides DoS | Benign, Probe, R2L | 98.6% | **78.5%** | 0.642 | 0.629 |
| Hides Probe | Benign, DoS, R2L | 99.1% | **79.8%** | 0.678 | 0.662 |
| Hides R2L | Benign, DoS, Probe | 99.9% | **88.1%** | 0.845 | 0.839 |

Per-class test F1: Benign 0.82–0.92 · DoS 0.88 · Probe 0.74–0.79 · **R2L 0.28–0.34** (R2L recall is only 16–21%).

### 3.2 Zero-day detection (the hidden family, never seen in training)

| Model | Hidden flows | Crossed the alert line | **Not called "normal"** | "Possible zero-day" alerts that were really the hidden family |
|---|---|---|---|---|
| Hides DoS | 7,454 | 70.2% | **98.2%** | 72.9% |
| Hides Probe | 2,421 | 72.5% | **88.6%** | 62.9% |
| Hides R2L | 2,814 | 1.1% | **37.4%** | 1.3% |

"Not called normal" counts every alert-bearing verdict, including review states, so it is not the same as
"correctly identified as the hidden attack" — the last column is the honest precision of the zero-day claim.

Attack *types* absent from the training file (17 types, 3,678 flows: mscan, apache2, snmpguess…) got an alert or
review **81.3–87.1%** of the time, while only 44.6% of them crossed the novelty line. Most of the rest were caught
as uncertain or known-candidate; **13–19% were still called Normal**, which is the honest miss rate for novel types.

### 3.3 False alarms on normal traffic (9,639 test flows)

| Model | Crossed the alert line (target 1%) | Auto-alerted | Sent to review | Total analyst burden |
|---|---|---|---|---|
| Hides DoS | 0.82% | 2.3% | 8.8% | 11.0% |
| Hides Probe | 0.82% | **6.0%** | 5.2% | 11.2% |
| Hides R2L | 0.82% | 2.3% | 4.0% | 6.3% |

Two different rates are easy to confuse, so keep them apart:

- **Threshold FPR** — how often a benign flow's anomaly score exceeds the frozen alert line. It held at **0.82%**
  against the 1% target, identical in all bundles because the novelty model and calibration rows are the same.
- **Verdict FPR** — how often a benign flow ends up in an alert-bearing verdict. It is much higher (2.3–6.0%)
  because it also includes classifier mistakes, not just the novelty gate. This is the number an analyst feels.

### 3.4 Confidence-bar coverage

The 95% conformal target is **not** met on KDDTest+, because its traffic mix differs from calibration:

| Model | Overall coverage | Benign | DoS | Probe | R2L |
|---|---|---|---|---|---|
| Hides DoS | 68.7% | 89.1% | — | 52.3% | 13.1% |
| Hides Probe | 69.6% | 89.0% | 67.6% | — | 8.5% |
| Hides R2L | 75.8% | 93.8% | 61.1% | 49.2% | — |

Per-class coverage is worst exactly where the classes are hardest (R2L), so the bars should be read as "how unusual
this flow is for that class", not as a guarantee. This is reported, not hidden, and is one reason the system leans on
review states.

### 3.5 Speed (CPU only, batched)

Measured by `pipeline.measure_performance` on the full test set:

| Bundle | Throughput | Median batch (1,000 flows) | Per flow | Explanation (mean) |
|---|---|---|---|---|
| Hides DoS | 4,164 flows/s | 234 ms | 0.24 ms | 99 ms |
| Hides Probe | 4,058 flows/s | 244 ms | 0.25 ms | 101 ms |
| Hides R2L | 4,093 flows/s | 236 ms | 0.24 ms | 151 ms |
| Probe (random split) | 4,199 flows/s | 233 ms | 0.24 ms | 100 ms |

Peak Python-traced memory during scoring was ~1.2 MB. Hardware recorded as `AMD64 Family 25 Model 80`.

How to read these: inference is **batched at 1,000 flows**, **no warm-up** is performed (first batch included), and
**explanation time is excluded** from throughput. Explanations are computed one alert at a time, only when opened,
and cost roughly 100–150 ms. These are not end-to-end console latencies: the live path scores single flows through
the engine and the UI updates on a 1-second stream, and there is no per-event latency instrumentation in
`server.py` to quote.

---

## 4. Things you should know

### About the numbers
- **Two accuracy figures, both honest.** Validation (same distribution as training) scores 98.6–99.9% macro-F1. The
  official test file was built to be harder, with new attack types and a shifted traffic mix, so it scores
  78.5–88.1% accuracy. Quote both, and say which is which.
- **The default model auto-alerts 6.0% of benign test flows**, not 1%. The 1% target applies only to the novelty
  gate (0.82%); classifier errors add the rest. If someone quotes "1% false positives", they are quoting the gate.
- **R2L is the weak spot.** Password-guessing and remote-login attacks look like normal sessions. The anomaly detector
  finds only 1.1% of them unusual, the classifier's R2L recall is 16–21% (F1 0.28–0.34), and only 1.3% of
  "possible zero-day" alerts for that bundle are real R2L. This is a known NSL-KDD difficulty, not a bug.
- **"Known" attacks can still come out Unclear.** In the current default model 632 of 665 smurf test flows are
  `KNOWN_ATTACK` and 33 are `UNCERTAIN_REVIEW`; the system says "not sure" rather than guessing. For a reliable
  "Known attack" demo, inject `neptune`.
- **Confidence-bar coverage is 69–76%, not 95%.** Conformal guarantees assume exchangeable data; KDDTest+
  deliberately is not. The drift panel shows this shift ("Yes, quite different"; max PSI 0.43 for the Probe model).
- **The alert line held:** 0.82% of normal test flows crossed it, against a 1% target.
- **Small families are reported, not hidden.** U2R has 67 test flows: 82% become alert-bearing, none are assigned a
  known candidate, 12 are called Normal. Read that as a limitation of the feature set, not a detection success.
- **Correlation is not scored in `metrics.json`.** The committed test metadata has no timestamps, so the burst/
  incident columns are disabled there (`enabled: false`, 0 groups). Correlation is exercised by tests and works in
  the console when metadata carries time and host.

### About running it
- **Restart the server after code changes** (`Ctrl+C`, then `python server.py`) and refresh the browser. Static
  responses are sent with `Cache-Control: no-cache` to make this reliable.
- **The console and `inject.py` must use the same model.** `inject.py` asks the running console which model it uses
  (`--console`, default `http://127.0.0.1:8000`). If you pass `--experiment` yourself and it differs, the console
  warns you in the UI.
- **Memory only.** The console keeps the newest 40,000 events in memory; restarting clears them. Only reviews are
  saved to disk (`feedback/feedback_log.jsonl`).
- **Localhost only.** The server binds 127.0.0.1 (`PORT` env var, default 8000) with no login. Don't expose it to a
  network as is.
- **Retraining overwrites.** `python run.py nsl_kdd --holdout Probe` replaces that bundle. Copy `artifacts/` first if
  you want to keep the old one.
- **Data and models are not in git** (`data/raw/`, `artifacts/`, `live/`, `feedback/` are ignored). A fresh clone
  needs the NSL-KDD files in `data/raw/nsl_kdd/` and one `run.py` run.
- **CIC-IDS2017 is implemented but unexercised.** `data/raw/cic_ids2017/` is empty here, so the loader, port
  ablation and correlation code paths have unit tests but no real-data result.

### About the design choices
- **Urgency weights are placeholders** (0.45 classifier / 0.30 anomaly / 0.10 entropy / 0.15 burst), not tuned.
  Urgency only sorts the queue; it never changes a verdict. Bands come from validation-score quantiles.
- **Rare families are excluded on purpose.** A family with fewer than 57 distinct training vectors cannot get a
  meaningful confidence bar, so it is treated as unseen instead.
- **Burst grouping never removes an alert.** Three or more non-Normal flows from one session/host within 30 s get an
  incident id; the burst signal is capped at 10 flows and feeds urgency only.
- **Drift is advisory.** PSI over the last 2,000 scored flows, minimum batch 500, bands at 0.10 / 0.25. It never
  changes a verdict or retrains anything.
- **Reviews never retrain the model.** Feedback is an audit log; retraining needs a reviewed dataset and a new run.
- **Confidence intervals** (Wilson) assume independent flows, so they are slightly optimistic.

### Tested vs not tested
- **47 automated tests** cover the decision table, fail-safes, calibration math, splits, leakage checks, quarantine,
  bundle tampering, every API endpoint, injection modes, explanation content, and the link between the confidence
  bars and real decisions.
- **Not automated:** the browser JavaScript (checked by manual/screenshot review at desktop width), phone and tablet
  layouts, live end-to-end latency, and CIC-IDS2017 on real data.
- There is no CI configuration; run `python -m pytest tests -q` before committing.

---

## 5. Future implementations

Ordered roughly by value for the effort.

| # | Idea | Why | Effort |
|---|---|---|---|
| 1 | **Run CIC-IDS2017** (loader, port ablation and burst grouping already built) | Modern 2017 traffic and attacks (DDoS, botnet, web attacks); tests the claims on a second dataset | Low (download ~1 GB, run `run.py`) |
| 2 | **Persist events** in SQLite | Alerts and investigations survive a restart | Low |
| 3 | **Tune urgency weights and display bands** on validation data | Removes the placeholder heuristic | Low |
| 4 | **Instrument end-to-end latency** (per-event score → stream → render) | The docs currently quote batch inference only, and the console's live path is unmeasured | Low |
| 5 | **Browser tests** (Playwright) and phone/tablet layout checks | The console UI has no automated tests today | Medium |
| 6 | **Live traffic sensor**: CICFlowMeter or Zeek turns packets into flow records feeding the inbox | Moves from simulation to real monitoring (needs a model trained on CIC-style features, and permission to monitor the network) | Medium–High |
| 7 | **Better R2L detection**: content and session-sequence features, or a per-family detector | Fixes the biggest blind spot | Medium |
| 8 | **Explain the anomaly detector itself** (validated SHAP for Isolation Forest) | Today only the classifier gets SHAP; the detector gets baseline deviations | Medium |
| 9 | **Model registry and promotion**: keep versions, compare, promote after review | Retraining stops overwriting; safe updates | Medium |
| 10 | **Feedback-driven retraining** from *verified* analyst reviews, with a fresh split and evaluation | Learns from the analysts without poisoning the model | Medium |
| 11 | **Session-aware confidence intervals** (block bootstrap by capture day) | More honest uncertainty in reported metrics | Low–Medium |
| 12 | **XGBoost / LightGBM comparison** against the histogram gradient-boosting classifier | May improve known-class accuracy | Low |
| 13 | **Login, roles, HTTPS**, and a Docker image | Needed before anyone else uses it on a network | Medium |
| 14 | **Cross-dataset transfer study** (train on CIC-IDS2017, test elsewhere) | Real generalisation evidence; needs a measurement-level feature mapping | High |

---

## 6. Quick reference

```bash
pip install -r requirements.txt
python run.py nsl_kdd --holdout Probe        # train + evaluate one model (also DoS, R2L)
python -m pytest tests -q                    # 47 tests
python server.py                             # console at http://127.0.0.1:8000 (PORT to change)
python inject.py                             # endless random stream, dashboard verdicts printed live
python inject.py list                        # what you can inject
python inject.py zero-day                    # simulated zero-day
python inject.py attack neptune              # a specific known attack
python inject.py mix --attack smurf          # normal + zero-day + smurf, shuffled
python inject.py synthetic                   # normal flows with features pushed out of range
python inject.py malformed                   # must show "Bad record", never Normal
python inject.py clear                       # empty the inbox
```
