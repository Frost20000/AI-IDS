# AI-IDS (CICIDS2017, RandomForest)

## Overview
Flow-based intrusion detection on CICIDS2017. We consolidate the daily CSVs into one flow table,
train a multiclass RandomForest, and save metrics and plots.

**Results (thesis run):**  
Accuracy 0.9848 · Macro-F1 0.8141 · Weighted-F1 0.9863  
*Sanity run (small mixed sample):* Acc 0.9998 · Macro-F1 0.6664 · Weighted-F1 0.9998

**Evaluation split:** Metrics are computed on the **held-out 20%** (stratified, `random_state=1`).

## Runtime (tested)
Python 3.12 · scikit-learn 1.4.x · numpy 2.0.x · pandas 2.2.x

## Quickstart
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
## Dataset layout (no data in git)

Monday-WorkingHours.pcap_ISCX.csv

Tuesday-WorkingHours.pcap_ISCX.csv

Wednesday-workingHours.pcap_ISCX.csv

Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv

Thursday-WorkingHours-Afternoon-Infiltration.pcap_ISCX.csv

Friday-WorkingHours-Morning.pcap_ISCX.csv

Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv

Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

## Build / Train / Evaluate

python -m src.data_prep --raw-dir data/raw/CICIDS2017 --out data/processed/flows.csv

python -m src.train_rf --csv data/processed/flows.csv --random-state 1 --n-estimators 400 --max-depth 100 --class-weight balanced_subsample --out-model models/rf_model.pkl --out-meta models/meta.json --reports-dir reports

python -m src.eval_rf --csv data/processed/flows.csv --model models/rf_model.pkl --meta models/meta.json --reports-dir reports

## Artifacts (in reports/)
metrics.json

classification_report.txt

confusion_matrix_counts.png

confusion_matrix_normalized.png

## Thesis sketch
See docs/thesis_sketch.md.

## How this works (short)
- **Data → flows.csv:** `src/data_prep.py` reads the CICIDS2017 daily CSVs, fixes headers, keeps the flow features, handles NaN/±inf, and writes `data/processed/flows.csv`.
- **Train:** `src/train_rf.py` fits a RandomForest (`n_estimators=400`, `class_weight=balanced_subsample`, `random_state=1`, `max_depth=100` here) and saves:
  - `models/rf_model.pkl` (model)  
  - `models/meta.json` (feature names, label map, split info)
- **Evaluate:** `src/eval_rf.py` loads the model and writes:
  - `reports/metrics.json` (accuracy, macro-F1, weighted-F1)  
  - `reports/classification_report.txt`  
  - `reports/confusion_matrix_counts.png`, `reports/confusion_matrix_normalized.png`

## Quick reviewer checklist
- Open `reports/metrics.json` → numbers match the README.  
- Open both confusion-matrix PNGs → classes align with the label map in `models/meta.json`.  
- `src/` has the three entry points: `data_prep.py`, `train_rf.py`, `eval_rf.py`.
