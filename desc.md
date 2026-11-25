# Megallen: Architecture, Accuracy and Roadmap

This document describes how Megallen is built today, how accurate it is, what you need to know before demoing or
extending it, and what should come next. For a shorter pitch-style overview see `project description.md`; for
setup commands see `README.md`.

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

---

## 2. Current architecture

### 2.1 Big picture

```
 data/raw/nsl_kdd/            run.py (offline training, ~30 s per model)
 KDDTrain+.txt  ─────────────►  load → clean → leakage audit → 5-way split
 KDDTest+.txt                   → train Random Forest + Isolation Forest
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
          ├─► 2b. Random Forest over known classes (e.g. BENIGN, DoS, R2L)
          │        each class has its own confidence bar (conformal calibration)  → which classes "fit"
          │
          └─► 3. Seven fixed decision rules (first match wins) → verdict
                 4. Urgency score 0-100 (sorting aid only, never changes the verdict)
                 5. Burst grouping: 3+ alerts from one host within 30 s
                 6. Explanation (summary, 3-step path, feature deviations, SHAP)
```

**The 7 decision rules**

| # | Unusual? | Known classes that fit | Verdict |
|---|---|---|---|
| 1 | No | exactly one attack class | Known attack |
| 2 | Yes | exactly one attack class | Known attack + "possible new variant" warning |
| 3 | No | only normal | Normal |
| 4 | Yes | only normal | Possible zero-day |
| 5 | Yes | none, or several | Possible zero-day |
| 6 | No | none, or several | Unclear |
| 7 | any | broken input or failed model | Bad record / Model problem (never Normal) |

### 2.3 Training pipeline (`run.py`)

1. **Load** each dataset with its own loader (NSL-KDD and CIC-IDS2017 are never mixed). Raw files are hashed (SHA-256)
   and never modified.
2. **Clean:** convert types, turn infinities into missing values, and quarantine rows with unknown labels or
   contradictory labels for identical feature vectors. Nothing is ever silently relabelled "normal".
3. **Leakage guard:** IPs, ports, timestamps, flow IDs, labels and NSL's "difficulty" column are kept out of the features.
4. **Split into 5 disjoint parts:** train · validation · normal-only calibration · conformal calibration · test.
   Identical feature vectors always stay in the same part. NSL-KDD keeps its official test file as the test set.
5. **Hide one attack family** (leave-one-family-out, "LOFO") from training, validation and calibration, so it can play
   the zero-day. Families too small to calibrate (U2R, 52 training rows) are also excluded and evaluated as unseen.
6. **Train** a class-weighted Random Forest (200 trees) and an Isolation Forest (200 trees, normal traffic only).
7. **Calibrate:**
   - Alert line: finite-sample rule `k = ⌈(n+1)(1−β)⌉` on 7,478 normal flows, β = 1%.
   - Per-class confidence bars: class-conditional split conformal, α = 0.05.
8. **Evaluate once** on the test set; write `metrics.json`.
9. **Save a bundle** atomically with a checksum manifest. The console refuses to load a bundle whose files changed.

### 2.4 Trained models today

| Bundle | Hidden attack family | Purpose |
|---|---|---|
| `nsl_kdd/lofo-probe-grouped` | Probe | Main model (console default) |
| `nsl_kdd/lofo-dos-grouped` | DoS | Zero-day test with DoS unseen |
| `nsl_kdd/lofo-r2l-grouped` | R2L | Zero-day test with R2L unseen |
| `nsl_kdd/lofo-probe-random` | Probe | Leakage audit only (random split); identical results to the grouped one |

Each bundle holds 2 ML models (Random Forest + Isolation Forest), so there are **8 trained models in total**, or
effectively 3 distinct setups. No CIC-IDS2017 model exists yet, because the data is not on this machine.

### 2.5 Code layout

| Path | Lines | Role |
|---|---|---|
| `ids/data.py` | 261 | Loaders, cleaning, quarantine, leakage audit, split, split manifest |
| `ids/core.py` | 171 | Calibration math, conformal sets, decision rules, urgency, burst grouping, drift (PSI) |
| `ids/pipeline.py` | 401 | Training, schema-checked inference, output record, explanations, evaluation, bundles |
| `ids/live.py` | 209 | Live inbox, attack catalogue, injection planning (normal / zero-day / specific attack / mix) |
| `ids/glossary.py` | 70 | Plain-English description of every feature |
| `run.py` | 100 | Train + evaluate one experiment |
| `inject.py` | 79 | Terminal tool to send simulated traffic |
| `server.py` | 438 | Detection engine thread + API |
| `web/` | ~1,160 | Console (no framework, no build step) |
| `tests/test_ids.py` | 433 | 45 test cases |

### 2.6 API (`server.py`, localhost only)

| Endpoint | Purpose |
|---|---|
| `GET /api/stream` | Server-sent events: new scored flows + state, every second |
| `GET /api/state` | Counts, replay progress, drift, model in use, injection/model mismatch |
| `POST /api/replay` | Start / pause / reset the test-set replay, set speed |
| `POST /api/bundle` | Switch model |
| `GET /api/attack-types` | Every injectable attack type and what it is to this model |
| `POST /api/inject` | Send normal / zero-day / specific attack / mix / stress-test traffic |
| `GET /api/events` | Filtered alert list |
| `GET /api/events/{id}` | One alert: summary sentence, rule fired, scores, confidence bars, output record |
| `GET /api/events/{id}/explain` | Feature deviations + TreeSHAP, in plain words |
| `POST /api/events/{id}/triage` | Record a review (append-only audit log) |
| `GET /api/model` | Alert line, confidence bars, top features (for "How it decides") |
| `GET /api/metrics` | Evaluation results of every bundle |

### 2.7 Explainable AI (where it lives)

| Layer | What the user sees | Source |
|---|---|---|
| Summary | One sentence per alert ("Flagged as a possible zero-day: its unusualness score 0.180 is above the alert line 0.075…") | `server.summary()` |
| Decision path | "Unlike normal traffic? Yes + Matches a known attack? No = Possible zero-day" | console |
| Step 1 | Gauge: score vs alert line | Isolation Forest + calibration |
| Step 2 | Each class's score vs its confidence bar ("fits" / "doesn't fit") | conformal calibration (unit-tested to match the real decision) |
| Step 3 | The rule that fired, out of 7 | `server.rule_for()` |
| Feature evidence | "Share of connections that failed to open is 0.86; normal is usually 0.00" | benign-baseline deviation (diagnostic, not causal) |
| Classifier evidence | Bars pushing towards or away from a class | TreeSHAP on the Random Forest |
| Global view | Top 8 features the classifier relies on, rules, glossary | `/api/model` |

### 2.8 Tech stack

Python 3.13 · pandas 2.3 · NumPy 2.3 · scikit-learn 1.7 · SHAP 0.51 · joblib · FastAPI 0.119 · Uvicorn 0.37 ·
plain HTML/CSS/JavaScript · Plotly.js 6.5 (served locally) · pytest 8.4.

---

## 3. Accuracy

All numbers come from each bundle's `metrics.json`. **Test = the official KDDTest+ file**: 22,544 flows, of which
22,395 were scored after quarantine. It was never used for training, tuning or calibration.

### 3.1 Known-attack classifier

| Model | Known classes | Validation macro-F1 | **Test accuracy** | Test macro-F1 | Test balanced accuracy |
|---|---|---|---|---|---|
| Hides DoS | Benign, Probe, R2L | 98.6% | **74.0%** | 0.532 | 0.543 |
| Hides Probe | Benign, DoS, R2L | 98.2% | **77.1%** | 0.575 | 0.595 |
| Hides R2L | Benign, DoS, Probe | 99.9% | **85.5%** | 0.821 | 0.794 |

Per-class test F1: Benign 0.81–0.88 · DoS 0.86 · Probe 0.73 · **R2L 0.03–0.05**.

### 3.2 Zero-day detection (the hidden family, never seen in training)

| Model | Hidden flows | Crossed the alert line | **Not called "normal"** | "Possible zero-day" alerts that were really the hidden family |
|---|---|---|---|---|
| Hides DoS | 7,454 | 70.2% | **90.3%** | 83.4% |
| Hides Probe | 2,421 | 72.5% | **99.8%** | 58.9% |
| Hides R2L | 2,814 | 1.1% | 66.0% | 1.1% |

Attack *types* absent from the training file (mscan, apache2, snmpguess…) got an alert or review **89.5–95.0%** of
the time.

### 3.3 False alarms on normal traffic (9,639 test flows)

| Model | Crossed the alert line (target 1%) | Auto-alerted | Sent to review |
|---|---|---|---|
| Hides DoS | 0.8% | 1.7% | 10.1% |
| Hides Probe | 0.8% | **0.8%** | 10.8% |
| Hides R2L | 0.8% | 1.4% | 11.5% |

### 3.4 Speed (CPU only)

About **2,650 flows per second**, 0.38 ms per flow in batches of 1,000. An explanation takes ~200 ms and is computed
only when an alert is opened.

---

## 4. Things you should know

### About the numbers
- **Two accuracy figures, both honest.** Validation (same distribution as training) scores 98–99.9% macro-F1. The
  official test file was built to be harder, with new attack types and a shifted traffic mix, so it scores 74–85.5%.
  Quote both, and say which is which.
- **R2L is the weak spot.** Password-guessing and remote-login attacks look like normal sessions. The anomaly detector
  finds only 1.1% of them unusual, and the classifier recognises only ~3–5%. This is a known NSL-KDD difficulty, not a bug.
- **"Known" attacks can still come out Unclear.** In a live test only 8 of 29 smurf flows were labelled Known attack;
  the rest were Unclear, because KDDTest+ smurf differs from training. The system says "not sure" instead of guessing.
  For a reliable "Known attack" demo, inject `neptune`.
- **Confidence-bar coverage is 64–69%, not 95%.** Conformal guarantees assume test data resembles calibration data;
  KDDTest+ deliberately does not. The drift panel shows this shift ("Large change").
- **The alert line held:** 0.8% of normal test flows crossed it, against a 1% target.

### About running it
- **Restart the server after code changes** (`Ctrl+C`, then `python server.py`) and refresh the browser.
- **The console and `inject.py` must use the same model.** `inject.py` now asks the running console which model it
  uses. If you pass `--experiment` yourself and it differs, the console warns you.
- **Memory only.** The console keeps the newest 40,000 events in memory; restarting clears them. Only reviews are
  saved to disk (`feedback/feedback_log.jsonl`).
- **Localhost only.** The server listens on 127.0.0.1 with no login. Don't expose it to a network as is.
- **Retraining overwrites.** `python run.py nsl_kdd --holdout Probe` replaces that bundle. Copy `artifacts/` first if
  you want to keep the old one.
- **Data and models are not in git** (`data/raw/`, `artifacts/`, `live/` and `feedback/` are git-ignored). A fresh clone needs
  the NSL-KDD files in `data/raw/nsl_kdd/` and one `run.py` run.
- **A lot of work is uncommitted.** The console (`server.py`, `web/`), injection, explanations and both description
  files have not been committed yet.

### About the design choices
- **Urgency weights are placeholders** (0.45 / 0.30 / 0.10 / 0.15), not tuned. Urgency only sorts the queue; it never
  changes a verdict.
- **Rare families are excluded on purpose.** A family with fewer than 57 distinct training vectors cannot get a
  meaningful confidence bar, so it is treated as unseen instead.
- **Reviews never retrain the model.** Feedback is an audit log; retraining needs a reviewed dataset and a new run.
- **Confidence intervals** (Wilson) assume independent flows, so they are slightly optimistic.

### Tested vs not tested
- 45 automated tests cover the decision table, fail-safes, calibration math, splits, leakage checks, every API
  endpoint, injection modes and the link between the confidence bars and real decisions.
- **Not automated:** the browser JavaScript, which was checked only by screenshots at 1600 px; phone and tablet layouts;
  and CIC-IDS2017 on real data.

---

## 5. Future implementations

Ordered roughly by value for the effort.

| # | Idea | Why | Effort |
|---|---|---|---|
| 1 | **Run CIC-IDS2017** (loader, port ablation and burst grouping already built) | Modern 2017 traffic and attacks (DDoS, botnet, web attacks); tests the claims on a second dataset | Low (download ~1 GB, run `run.py`) |
| 2 | **Persist events** in SQLite | Alerts and investigations survive a restart | Low |
| 3 | **Tune urgency weights and display bands** on validation data | Removes the placeholder heuristic | Low |
| 4 | **Browser tests** (Playwright) and phone/tablet layout checks | The console UI has no automated tests today | Medium |
| 5 | **Live traffic sensor**: CICFlowMeter or Zeek turns packets into flow records feeding the inbox | Moves from simulation to real monitoring (needs a model trained on CIC-style features, and permission to monitor the network) | Medium–High |
| 6 | **Better R2L detection**: content and session-sequence features, or a per-family detector | Fixes the biggest blind spot | Medium |
| 7 | **Explain the anomaly detector itself** (validated SHAP for Isolation Forest) | Today only the classifier gets SHAP; the detector gets baseline deviations | Medium |
| 8 | **Model registry and promotion**: keep versions, compare, promote after review | Retraining stops overwriting; safe updates | Medium |
| 9 | **Feedback-driven retraining** from *verified* analyst reviews, with a fresh split and evaluation | Learns from the analysts without poisoning the model | Medium |
| 10 | **Session-aware confidence intervals** (block bootstrap by capture day) | More honest uncertainty in reported metrics | Low–Medium |
| 11 | **XGBoost / LightGBM comparison** against the Random Forest | May improve known-class accuracy | Low |
| 12 | **Login, roles, HTTPS**, and a Docker image | Needed before anyone else uses it on a network | Medium |
| 13 | **Cross-dataset transfer study** (train on CIC-IDS2017, test elsewhere) | Real generalisation evidence; needs a measurement-level feature mapping | High |

---

## 6. Quick reference

```bash
pip install -r requirements.txt
python run.py nsl_kdd --holdout Probe        # train + evaluate one model (also DoS, R2L)
python -m pytest tests -q                    # 45 tests
python server.py                             # console at http://127.0.0.1:8000
python inject.py list                        # what you can inject
python inject.py zero-day                    # simulated zero-day
python inject.py attack neptune              # a specific known attack
python inject.py mix --attack smurf          # normal + zero-day + smurf, shuffled
```
