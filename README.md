# AI-IDS (CICIDS2017, RandomForest)

## Overview
Flow-based intrusion detection on CICIDS2017. We consolidate the daily CSVs into one flow table, train a multiclass RandomForest, and save metrics and plots.

**Results (thesis run)**  
Accuracy 0.9848 · Macro-F1 0.8141 · Weighted-F1 0.9863

**Evaluation split**  
Metrics are computed on a held-out 20% (stratified, `random_state=1`).

## Runtime (tested)
Python 3.12 · scikit-learn 1.4.x · NumPy 2.0.x · pandas 2.2.x

## Get the dataset (download & extract)

CICIDS2017 is published by the Canadian Institute for Cybersecurity (UNB).

- Official page (terms + download): https://www.unb.ca/cic/datasets/ids-2017.html  
  *Note:* some downloads require a short form; it’s free to use for research/education.
- Mirrors (e.g., Kaggle) exist, but the UNB page is the authoritative source.

**Steps**

1. Download the **CSV flow files** for each day (Mon–Fri).  
   Filenames look like: `Monday-WorkingHours.pcap_ISCX.csv`, …, `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`.
2. Create the folder and copy all eight CSVs into it:
   - Linux/macOS:
     ```bash
     mkdir -p data/raw/CICIDS2017
     mv ~/Downloads/*pcap_ISCX.csv data/raw/CICIDS2017/
     ```
   - Windows (PowerShell):
     ```powershell
     New-Item -ItemType Directory -Force data\raw\CICIDS2017 | Out-Null
     Copy-Item "$env:USERPROFILE\Downloads\*pcap_ISCX.csv" data\raw\CICIDS2017\
     ```

## Repository structure

- `data/`
  - `raw/CICIDS2017/` — put the 8 daily CSVs here (not tracked)
  - `processed/` — `flows.csv` written by `data_prep`
- `models/` — `rf_model.pkl`, `meta.json`
- `reports/` — `metrics.json`, `classification_report.txt`, `confusion_matrix_*.png`
- `src/`
  - `data_prep.py` — build `flows.csv` (37 features + `Label`)
  - `train_rf.py` — RandomForest training
  - `eval_rf.py` — evaluation (metrics + confusion matrices)
- `scripts/`
  - `validate_data.py` — checksum/schema/class-distribution checks
- `docs/`
  - `thesis_sketch.md`

## Dataset layout (no data in git)
Expected files in `data/raw/CICIDS2017/`:
- Monday-WorkingHours.pcap_ISCX.csv  
- Tuesday-WorkingHours.pcap_ISCX.csv  
- Wednesday-workingHours.pcap_ISCX.csv  
- Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv  
- Thursday-WorkingHours-Afternoon-Infiltration.pcap_ISCX.csv  
- Friday-WorkingHours-Morning.pcap_ISCX.csv  
- Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv  
- Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

## Quickstart
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

# 1) Build consolidated flows.csv from daily CSVs
python -m src.data_prep --raw-dir data/raw/CICIDS2017 --out data/processed/flows.csv

# 2) Train RandomForest
python -m src.train_rf \
  --csv data/processed/flows.csv \
  --random-state 1 \
  --n-estimators 400 \
  --max-depth 100 \
  --class-weight balanced_subsample \
  --out-model models/rf_model.pkl \
  --out-meta  models/meta.json

# 3) Evaluate on held-out 20% (stratified, seed=1)
python -m src.eval_rf \
  --csv   data/processed/flows.csv \
  --model models/rf_model.pkl \
  --meta  models/meta.json \
  --reports-dir reports

  
## Artifacts (written to reports/)

metrics.json

classification_report.txt

confusion_matrix_counts.png

confusion_matrix_normalized.png

## Data integrity check

python scripts/validate_data.py --raw-dir data/raw/CICIDS2017 --flows data/processed/flows.csv
This confirms the 8 files are present, header/schema (incl. Label) are correct, prints per-class counts, and writes checksums to reports/checksums.txt.

## Baseline (for comparison)
python -m src.train_logreg --csv data/processed/flows.csv --reports-dir reports
