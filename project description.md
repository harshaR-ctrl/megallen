# Megallen: Open-World Intrusion Detection with Explainable Zero-Day Alerts

## 1. Summary

Megallen is an offline network intrusion detection system built to answer a question most classifiers cannot:
**"Is this traffic an attack I have never seen before?"**

A normal intrusion classifier must pick one of the labels it was trained on, so a brand-new attack gets
silently mislabelled as "normal" or as the nearest known attack. Megallen combines two independent models with
calibrated uncertainty and fixed decision rules. Traffic that is **unlike normal behaviour and matches no known
attack** is reported as a **possible zero-day** instead of being forced into a known label. Every verdict comes
with a plain-English explanation of why it was given.

The system runs on public labelled datasets (NSL-KDD now, CIC-IDS2017 supported) and includes a real-time
analyst console where you can replay test traffic, inject simulated zero-day attacks from a second terminal,
and investigate each alert.

> Scope: offline defensive research. Traffic is replayed from datasets or injected as stored records.
> No packets are captured or sent, and "zero-day" means an attack family deliberately hidden from training,
> not a real-world zero-day.

## 2. Problem

| Problem with typical IDS research | How Megallen handles it |
|---|---|
| Closed-set classifiers force unknown attacks into known labels | A benign-only novelty detector plus conformal prediction sets let the system answer "none of the above" |
| Anomaly detectors alone raise too many false alarms | The novelty threshold is calibrated to a 1% benign false-alarm budget on held-out normal traffic |
| High reported accuracy often comes from data leakage | Identifiers excluded from features, duplicate-aware splits, five disjoint partitions, leakage audit in every run |
| Models give a label but no reason | Every alert shows the checks, the rule that fired, the features that made it unusual, and SHAP values |
| Pipelines silently turn errors into "normal" | Missing models, schema mismatches or invalid outputs can never produce a NORMAL verdict |

## 3. How it works

```
 flow record
     │
     ▼
 1. Input check ──── broken schema / types ──────────────────────────► BAD RECORD (never "normal")
     │
     ├──────────────────────────────┐
     ▼                              ▼
 2a. Unusual-traffic detector    2b. Attack classifier
     Isolation Forest trained        Random Forest (class-weighted) over
     ONLY on normal traffic          known classes, with a per-class
     score vs calibrated alert line  conformal confidence bar
     │                              │
     └──────────────┬───────────────┘
                    ▼
 3. Decision rules (7 fixed rules, first match wins)
                    ▼
 4. Verdict: Possible zero-day · Known attack · Unclear · Normal · Bad record · Model problem
                    ▼
 5. Urgency score (0–100, triage heuristic) + incident grouping + explanation
```

**Decision rules**

| # | Unusual? | Known classes that fit | Verdict |
|---|---|---|---|
| 1 | No | Exactly one attack class | Known attack |
| 2 | Yes | Exactly one attack class | Known attack, flagged as a possible new variant |
| 3 | No | Only normal | Normal |
| 4 | Yes | Only normal | **Possible zero-day** |
| 5 | Yes | None, or several | **Possible zero-day** |
| 6 | No | None, or several | Unclear, needs a person |
| 7 | Any | Input broken or a model failed | Bad record / Model problem, never Normal |

## 4. Innovation

1. **Open-world verdicts, not just labels.** The system can say "this matches nothing I know", which is the
   core requirement for zero-day detection and which standard classifiers cannot express.
2. **Two-signal fusion with calibrated guarantees.**
   - The alert line uses a finite-sample order-statistic rule, `k = ⌈(n+1)(1−β)⌉`, on 7,478 held-out normal
     flows, targeting ≤1% benign false alarms.
   - Each attack class gets its own **class-conditional split-conformal** confidence bar (α = 0.05). So
     "no class fits" is a statistically grounded statement, not an arbitrary cutoff.
3. **Deterministic, auditable decisions.** A fixed truth table, not "whichever model ran last", decides every
   verdict. Each alert names the exact rule that fired, and every rule has a unit test.
4. **Leave-one-family-out (LOFO) evaluation.** Each experiment removes a whole attack family (DoS, Probe or
   R2L) from training, validation and calibration, then measures how often the system catches it as unknown.
   That is a measurable proxy for zero-day detection.
5. **Leakage-audited by construction.**
   - IPs, ports, timestamps, flow IDs, labels and the NSL "difficulty" field are excluded from features.
   - Identical feature vectors never cross partitions.
   - Normal-traffic calibration and conformal calibration use disjoint records.
   - Attack families too rare to calibrate (U2R) are evaluated as unseen instead of producing meaningless bars.
6. **Explainable AI built into the workflow.** Each alert explains itself in three layers:
   - a plain-English summary sentence
   - a three-step decision path: unusualness against the alert line, each class against its confidence bar,
     and the rule that fired
   - feature-level evidence: deviation from normal traffic described in sentences, plus TreeSHAP values of
     the classifier

   A "How it decides" page shows global feature importance and a glossary.
7. **Fail-safe engineering.**
   - Schema mismatches, missing models and NaN outputs route to review states, never to "normal".
   - Model bundles are checksum-verified before loading.
   - Analyst feedback goes to an append-only log and never retrains the model automatically.
8. **Live demo console.**
   - Real-time streaming (server-sent events).
   - Inject simulated zero-day, unusual, known, benign or malformed traffic from a second terminal or a button.
   - Triage alerts with keyboard shortcuts.
   - Watch drift (PSI) and incident grouping.

## 5. Tech stack

| Layer | Technology | Role |
|---|---|---|
| Language | Python 3.13 | Pipeline, models, server |
| Data | pandas 2.3, NumPy 2.3 | Loading, cleaning, schema validation, audits |
| Machine learning | scikit-learn 1.7 | `RandomForestClassifier` (class-weighted), `IsolationForest`, `ColumnTransformer` preprocessing |
| Calibration | NumPy (project code) | Finite-sample anomaly threshold, class-conditional split-conformal sets |
| Explainability | SHAP 0.51 (TreeSHAP), project glossary | Per-alert attributions, baseline deviation, plain-English feature descriptions |
| Drift | NumPy | Population Stability Index on fixed training bins |
| Persistence | joblib + JSON manifests (SHA-256) | Versioned, checksum-verified model bundles |
| Backend | FastAPI 0.119, Uvicorn 0.37 | REST API, server-sent-event stream, detection engine thread (localhost only) |
| Frontend | HTML, CSS, vanilla JavaScript, Plotly.js 6.5 | Analyst console, no build step, no framework |
| Testing | pytest 8.4 | 43 tests: decision table, fail-safes, calibration math, splits, leakage, API, XAI consistency |
| Datasets | NSL-KDD (KDDTrain+ / KDDTest+), CIC-IDS2017 loader | Separate pipelines, never mixed |

**Project layout**

| Path | Contents |
|---|---|
| `ids/data.py` | Dataset loaders, cleaning, quarantine, leakage audit, split manifests |
| `ids/core.py` | Calibration, conformal sets, decision rules, priority, correlation, PSI |
| `ids/pipeline.py` | Training, schema-validated inference, explanations, evaluation, bundles |
| `ids/live.py`, `inject.py` | Live inbox and simulated attack injection |
| `ids/glossary.py` | Plain-English descriptions of every feature |
| `run.py` | Train and evaluate one experiment |
| `server.py`, `web/` | Console backend and frontend |
| `tests/test_ids.py` | Test suite |

## 6. Model accuracies

All numbers come from the saved evaluation of each model bundle (`artifacts/nsl_kdd/*/metrics.json`).
"Test" is the official **KDDTest+** file: 22,544 flows, of which 22,395 were scored after rows with conflicting
labels were quarantined. It was never used for training, tuning or calibration.

### 6.1 Known-attack classifier (Random Forest)

| Model (held-out family) | Known classes | Validation macro-F1 | Test accuracy | Test macro-F1 | Test balanced accuracy |
|---|---|---|---|---|---|
| Hides DoS | Benign, Probe, R2L | 98.6% | 74.0% | 0.532 | 0.543 |
| Hides Probe | Benign, DoS, R2L | 98.2% | 77.1% | 0.575 | 0.595 |
| Hides R2L | Benign, DoS, Probe | **99.9%** | **85.5%** | **0.821** | **0.794** |

Per-class test F1:

| Model | Benign | DoS | Probe | R2L |
|---|---|---|---|---|
| Hides DoS | 0.830 | held out | 0.733 | 0.033 |
| Hides Probe | 0.807 | 0.863 | held out | 0.054 |
| Hides R2L | 0.878 | 0.857 | 0.727 | held out |

**Why validation and test differ.** Validation flows come from the same file and distribution as training
(98–99.9% macro-F1). KDDTest+ was built to be harder: it contains attack types absent from the training
file and a shifted traffic mix. That especially hurts R2L, which has only 995 training examples and looks
very similar to normal logins. The gap is a known property of NSL-KDD and is reported here instead of hidden.

### 6.2 Zero-day detection (held-out family never seen in training)

| Model | Held-out test flows | Caught by unusual-traffic detector | Not called "normal" (any alert or review) | Precision of "possible zero-day" |
|---|---|---|---|---|
| Hides DoS | 7,454 | 70.2% | 90.3% | 83.4% |
| Hides Probe | 2,421 | 72.5% | **99.8%** | 58.9% |
| Hides R2L | 2,814 | 1.1% | 66.0% | 1.1% |

Attack *types* that never appear in the training file (for example mscan, apache2, snmpguess) received an
alert or review verdict **89.5–95.0%** of the time. The rare U2R family, excluded from training because it is
too small to calibrate, got one **91–94%** of the time in the DoS and Probe models.

**Honest limitation:** R2L attacks (password guessing, remote logins) look like normal sessions, so a detector
trained on normal behaviour almost never finds them unusual (1.1%). The system still sends 66% of them to an
analyst, but zero-day detection by anomaly alone does not work for this family.

### 6.3 False alarms on normal traffic (test set, 9,639 benign flows)

| Model | Novelty alarms on normal traffic (target 1%) | Normal traffic auto-alerted | Normal traffic sent for review |
|---|---|---|---|
| Hides DoS | 0.8% | 1.7% | 10.1% |
| Hides Probe | 0.8% | **0.8%** | 10.8% |
| Hides R2L | 0.8% | 1.4% | 11.5% |

The calibrated alert line held its 1% target on unseen test data (0.8% in every model).

### 6.4 Uncertainty calibration

Conformal coverage on the test set was **64–69%** against a 95% target. Coverage guarantees assume test traffic
resembles calibration traffic, and KDDTest+ deliberately does not. The drop is a measurement of that
distribution shift, and the drift monitor flags it (PSI up to 0.44, "significant shift").

### 6.5 Speed (CPU only, AMD Ryzen laptop)

| Metric | Value |
|---|---|
| Throughput | ~2,650 flows per second |
| Latency per flow | ~0.38 ms (batches of 1,000) |
| Explanation latency (TreeSHAP + deviations) | ~200 ms per alert, computed only on request |

### 6.6 Leakage checks (all passed)

- Held-out family absent from training, validation and conformal calibration.
- Normal-traffic calibration set contains only benign flows.
- All partitions disjoint; the two calibration sets share no records.
- No identifier, label, timestamp or difficulty column in the feature matrix.
- The row-random vs duplicate-grouped split comparison gave identical results on NSL-KDD, which already
  has duplicates removed by design. The comparison will matter on CIC-IDS2017.

## 7. Running it

```bash
pip install -r requirements.txt
python run.py nsl_kdd --holdout Probe      # train + evaluate (≈30 s); also DoS, R2L
python -m pytest tests -q                  # 43 tests
python server.py                           # console at http://127.0.0.1:8000
python inject.py zero-day                  # second terminal: send a simulated zero-day
```

## 8. Limitations and next steps

- **CIC-IDS2017 not yet evaluated.** The loader, the port ablation and temporal grouping are built and
  tested on synthetic data, but the full dataset has not been run.
- **Some attack families are invisible to anomaly detection.** Families that mimic normal behaviour, like R2L,
  need content or sequence features beyond flow statistics.
- **Urgency weights are provisional.** The placeholders (0.45 / 0.30 / 0.10 / 0.15) have not been tuned.
- **Confidence intervals assume independent flows.** A session-aware block bootstrap would give more honest
  ones.
- **No live packet capture by design.** A deployment would also need sensor integration, authentication and
  model-promotion workflows.
