# Technology Stack

## 1. Project Overview

**Project:** Leakage-Audited Open-World Hybrid Intrusion Detection System

**Goal:** Recognize known attack categories, identify unusual traffic that differs from benign behaviour, keep uncertain records visible for review, and explain important alert signals.

**Scope:** Offline experimentation and controlled replay of CIC-IDS2017 and NSL-KDD. No live production network monitoring, packet injection, attack generation, or offensive scanning is part of the first release.

## 2. Core Technology Stack

| Layer | Technology | Purpose / boundary |
|---|---|---|
| Language | Python 3.10+ | Main implementation language; use one tested Python environment for each release |
| Data processing | Pandas, NumPy | Load, clean, validate, transform, and inspect dataset records |
| Dataset storage | CSV for raw input; Parquet optional for processed data | Keep raw data immutable; Parquet is a derived cache, not a replacement for provenance |
| ML pipelines | scikit-learn | Dataset splits, preprocessing, Random Forest, Isolation Forest, metrics, and pipelines |
| Supervised model | `RandomForestClassifier` with class weighting | Known-class classification baseline |
| Novelty model | `IsolationForest` | Fit only on benign training rows to model normal-behaviour boundaries |
| Categorical processing | scikit-learn `ColumnTransformer`, `SimpleImputer`, `OneHotEncoder` or an explicit unknown-category mapping | Separate numeric and categorical preprocessing; handle unseen values safely |
| Calibration | NumPy + small tested project utilities | Finite-sample anomaly threshold and class-conditional split conformal sets; do not implement ad-hoc interpolated quantiles |
| Explainable AI | SHAP `TreeExplainer` (optional dependency) | Explain supported supervised tree-model predictions on selected alerts |
| Drift monitoring | NumPy, Pandas | Compute PSI from fixed training-baseline bins |
| Dashboard | Streamlit | Offline replay, operations monitor, alert triage, and research results |
| Visualisation | Plotly | Traffic, scores, thresholds, metrics, and drift charts |
| API | FastAPI + Uvicorn (optional, later phase) | Expose the stable inference function after the offline pipeline works |
| Model persistence | Joblib | Save trusted local preprocessing and model artifacts |
| Processed data | PyArrow (optional) | Parquet read/write support |
| Testing | Pytest | Test data contracts, preprocessing, calibration, policy decisions, and replay |
| Version control | Git + GitHub | Track code, configuration, documentation, and experiment changes |

Do not call the baseline a “Balanced Random Forest” unless using the separate `BalancedRandomForestClassifier` implementation. The default stack uses scikit-learn's class-weighted `RandomForestClassifier`; this avoids adding an unnecessary imbalanced-learn dependency in the first release.

## 3. Recommended Implementation Choices

### Supervised classifier

- Start with `RandomForestClassifier(class_weight="balanced_subsample")` or another explicitly documented class-weight policy.
- Save the exact class order used by `predict_proba`.
- Add XGBoost only after the complete baseline pipeline is reproducible and tested.
- Do not assume raw `predict_proba` values are perfectly calibrated. Call them model scores unless calibration quality has been measured.

### Novelty detector

- Use scikit-learn `IsolationForest`.
- Fit the model only on benign training records.
- Use a separate novelty preprocessing path; fit numeric imputation/scaling on benign training records.
- For categorical values, reserve an explicit unknown bucket so categories absent from benign training are not silently lost.
- Convert continuous model scores so higher application-level values always mean more anomalous.
- Do not use `IsolationForest.predict()` or its `contamination`-derived label cutoff as the deployed FPR policy.
- Set the operating threshold using a disjoint benign-only anomaly-calibration partition and an explicit finite-sample order-statistic rule.

### Preprocessing

- Use `ColumnTransformer` and `Pipeline` to keep transformations reproducible.
- Fit classifier preprocessing on classifier training rows only.
- Fit novelty numeric statistics on benign training rows only.
- Use train-fitted categorical handling and an explicit strategy for unseen categories.
- Use `RobustScaler` only where justified; tree models do not automatically require scaling. Any scaler must be fitted on the correct training subset.
- Never fit imputation, encoding, feature selection, or scaling on validation/calibration/test data.

### Calibration

- Implement the finite-sample quantile convention in one shared tested utility.
- Keep benign FPR threshold calibration and labelled conformal calibration in separate record partitions.
- Record target FPR, alpha, sample counts, order-statistic index, quantile values, and insufficient-sample fallback states.
- Do not use test data to select either calibration threshold.

### Explainability and drift

- Add SHAP after the known-class classifier is stable. Explain flagged/uncertain records only.
- Verify multiclass SHAP output shape for the installed model and SHAP versions.
- If Isolation Forest attribution is not validated, show benign-baseline deviations and label them as such, not SHAP.
- Compute PSI against fixed training-baseline bins, with smoothing and a minimum batch-size policy.
- Drift is a warning only; no automatic retraining or threshold changes.

### Dashboard and API

- Prioritize a working Streamlit dashboard before FastAPI.
- Label every replay as offline dataset simulation.
- Display detection verdict, novelty flag, conformal set, and triage priority separately.
- Keep every original flow alert visible after temporal grouping.
- Add FastAPI only after a single tested inference function and output schema exist.

## 4. Dataset Rules

### CIC-IDS2017 — primary dataset

Use as the main development and open-world demonstration dataset.

- Build a dedicated loader; validate schemas per file before concatenation.
- Normalize label spelling explicitly and retain original labels.
- Preserve source file, row number, IPs, timestamps, ports, and Flow ID as appropriate metadata; never feed identifiers into the model matrix.
- Audit duplicates, conflicting labels, collection-session artifacts, and feature-vector overlap across splits.
- Run with-port and no-port experiments with the same split manifest.
- Hold out complete attack families from supervised training and conformal calibration for LOFO evaluation.
- Use a separate benign-only calibration partition for the Isolation Forest threshold.

### NSL-KDD — secondary benchmark

Use as an independent benchmark, not an extension of the CIC feature table.

- Load official train and test files with the documented feature order.
- Preserve original attack labels and document binary/family mappings.
- Exclude the target label and difficulty field from model features.
- Encode protocol type, service, and flag using train-fitted handling with explicit unknown-category behaviour.
- Derive validation and both calibration partitions from the official training portion only; preserve the official test file.
- Report all metrics separately from CIC-IDS2017.

A cross-dataset transfer experiment is optional and must define a measurement-level common feature mapping. Do not claim transfer merely because two columns have similar names.

## 5. Development Environment

Create an isolated environment and install from a tested requirements file:

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
```

Suggested base `requirements.txt` package set (pin versions after verifying the environment):

```text
pandas
numpy
scikit-learn
streamlit
plotly
joblib
pytest
```

Optional extras, added only when their phase begins:

```text
shap       # selective supervised-tree explanations
pyarrow    # Parquet read/write
fastapi    # optional inference API
uvicorn    # optional API server
xgboost    # optional model comparison
```

Avoid installing unused optional dependencies in the first baseline environment. Avoid unbounded dependency changes after producing the final evaluation; save exact installed versions in the run manifest or lock file.

## 6. Hardware and Performance Expectations

- CPU-based development is sufficient for the proposed tree-based models and a moderate offline demonstration.
- A GPU is not required for Random Forest, Isolation Forest, or the planned dashboard.
- Begin with a small, deterministic sample to validate the end-to-end pipeline, then run the full selected dataset.
- Use batch replay and cache trusted local model loading to keep Streamlit responsive.
- Measure throughput, per-flow/batch inference latency, explanation latency, and peak memory separately. Record hardware, batch size, warm-up policy, and dataset size.
- Do not report a benchmark without stating whether SHAP explanation time is included.

## 7. Artifact and Runtime Safety

- Store separate model bundles for CIC-IDS2017 and NSL-KDD, and separate bundles for each feature experiment such as with-port/no-port.
- Save feature names/order/types, class order, preprocessing objects, calibration thresholds/quantiles, score directions, split manifest, random seeds, metrics, dependency versions, and code commit.
- Validate dataset ID, schema, feature order, class order, and artifact version before inference.
- Write artifacts atomically and verify their manifest/checksum.
- Load Joblib files only when created by this project and stored in a trusted location. Never accept arbitrary uploaded `.joblib`/pickle files from users; deserialization can execute code.
- Do not serialize NaN/Infinity in strict JSON. Use `null` plus an explicit status field.
- Reject invalid schema or failed model output; never convert pipeline errors into a benign prediction.

## 8. Final Stack Decision

**First complete release:**

Python + Pandas + NumPy + scikit-learn + class-weighted Random Forest + benign-only Isolation Forest + Streamlit + Plotly + Joblib + Pytest.

**Add after the baseline is stable:**

Class-conditional conformal calibration, finite-sample FPR thresholding, SHAP explanations, PSI monitoring, and (optionally) FastAPI.

This order produces a working end-to-end demonstrator early while keeping the more delicate calibration and explainability components testable and auditable.
