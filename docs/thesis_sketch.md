# Thesis sketch — AI-IDS (flow-based IDS on CICIDS2017)

**Problem.** Detect network attacks from flow statistics (no payload) using CICIDS2017.

**Goal.** Train and evaluate a multiclass model; provide reproducible code, saved metrics/plots, and a small demo stub.

**Dataset.** CICIDS2017 daily CSVs (Mon–Fri). 37 flow features: packet/byte counts, IATs, flags, simple rates. Raw data is not stored in the repo.

**Method.**
- Build a single `flows.csv` from daily files; normalize headers; handle NaN/±inf.
- Model: RandomForest (`n_estimators=400`, `class_weight=balanced_subsample`, `random_state=1`, `max_depth=100` here).
- Split 80/20 (seed=1). Metrics: accuracy, macro-F1, weighted-F1. Save confusion matrices and a text report.

**Results (thesis run).** Accuracy 0.9848 · Macro-F1 0.8141 · Weighted-F1 0.9863.  
*A small mixed “sanity run” is included for quick verification.*

**Outputs.**
- `models/rf_model.pkl`, `models/meta.json`
- `reports/metrics.json`, `reports/classification_report.txt`,
  `reports/confusion_matrix_counts.png`, `reports/confusion_matrix_normalized.png`

**Limitations.** Class imbalance affects macro-F1; flow-level features only (no payload). Max depth capped for the CLI; this does not change conclusions.

**What to review quickly.** README “How it works”, reports PNGs/JSON, and `src/` modules (`data_prep`, `train_rf`, `eval_rf`).
