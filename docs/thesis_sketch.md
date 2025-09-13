# Thesis sketch — AI-IDS (CICIDS2017)

## Scope
Detect network attacks from **flow statistics** (no payload). Train and evaluate a **multiclass** model on CICIDS2017. Provide end-to-end code and keep evaluation artifacts in the repo.

## Data
- Source: CICIDS2017 daily CSVs (Mon–Fri).
- Storage: raw CSVs are **not** in git; expected path: `data/raw/CICIDS2017/`.
- Features: 37 flow features (packet/byte counts, inter-arrival times, header flags, simple rates).
- Labels: the label map used by the model is stored in `models/meta.json` (`label_names`).

## Method (how it works)
1. **Prepare flows** — `src/data_prep.py`  
   - reads the daily CSVs  
   - normalizes headers (ensures `Label`) and coerces types  
   - handles NaN and ±∞ (replace where safe; drop rows still invalid)  
   - writes `data/processed/flows.csv` (37 features + `Label`)
2. **Train** — `src/train_rf.py`  
   - algorithm: `RandomForestClassifier`  
   - params: `n_estimators=400`, `class_weight=balanced_subsample`, `random_state=1`, `max_depth=100` (CLI requires an int here)  
   - split: **stratified 80/20 by label** (`random_state=1`)  
   - saves `models/rf_model.pkl` and `models/meta.json`
3. **Evaluate** — `src/eval_rf.py`  
   - metrics on the **held-out 20%**: Accuracy, Macro-F1, Weighted-F1  
   - artifacts: `reports/metrics.json`, `reports/classification_report.txt`, `reports/confusion_matrix_counts.png`, `reports/confusion_matrix_normalized.png`

## Results (thesis run)
Accuracy **0.9848** · Macro-F1 **0.8141** · Weighted-F1 **0.9863**  
A small mixed **sanity run** is included for a quick environment check (numbers shown in the README).

## Reproducibility
- Environment: see `requirements.txt` (Python and packages pinned).  
- Seed: `random_state=1` (split and model).  
- Feature names and label map are in `models/meta.json`.  
- Reproducibility is demonstrated by the three commands in the README (**Build / Train / Evaluate**).

## Outputs in the repo
- **Model:** `models/rf_model.pkl`, `models/meta.json`  
- **Reports:** `reports/metrics.json`, `reports/classification_report.txt`, `reports/confusion_matrix_counts.png`, `reports/confusion_matrix_normalized.png`

## Limitations
- Class imbalance lowers Macro-F1 relative to Accuracy/Weighted-F1.  
- Flow-level features only (no payload).  
- `max_depth=100` is used to satisfy the CLI; this choice does **not** change the thesis conclusions.

## Quick review guide
- The three metrics are recorded in `reports/metrics.json`.  
- Confusion-matrix PNGs show class distribution/errors; labels match `models/meta.json`.  
- Entry points in `src/`: `data_prep.py`, `train_rf.py`, `eval_rf.py`.
