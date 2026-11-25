# Leakage-Audited Open-World Hybrid IDS

Offline defensive research demonstrator: a class-weighted Random Forest (known attacks), a benign-only
Isolation Forest (novelty gate), class-conditional split conformal sets (uncertainty), and a deterministic
decision table, with temporal grouping, a heuristic triage priority, TreeSHAP/baseline explanations, PSI drift
and a Streamlit dashboard. Design specs: `architecture (1).md`, `pipeline (1).md`, `techstack (1).md`, `workflow (1).md`.

**Scope:** replays labelled public-dataset records offline. It is not a live sensor and does not establish
real-world zero-day detection.

## Layout

| Path | What |
|---|---|
| `ids/data.py` | Separate CIC-IDS2017 / NSL-KDD loaders, cleaning, quarantine, leakage audit, split manifests |
| `ids/core.py` | Finite-sample threshold, conformal sets, decision table, priority, correlation, PSI |
| `ids/pipeline.py` | Training, schema-validated inference, output contract, explanations, evaluation, bundles |
| `run.py` | One experiment end to end -> `artifacts/<dataset>/<experiment_id>/` |
| `app.py` | Dashboard: Operations Monitor, Alert Triage, Research Proof |
| `tests/test_ids.py` | Checklist tests (decision table, fail-safes, calibration, splits, leakage, bundle integrity) |
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
streamlit run app.py
```

Defaults: seed 42, conformal alpha 0.05, target benign FPR 0.01, 200 trees. All arguments, file hashes,
versions and the git commit go into `run_manifest.json`.

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
