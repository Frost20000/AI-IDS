# AI-IDS (CICIDS2017, RandomForest)

## Overview
Flow-based intrusion detection on CICIDS2017. We build one flow table from the daily CSVs,
train a multiclass RandomForest, and report accuracy, macro-F1, weighted-F1 with saved plots.

**Results (thesis run):**
Accuracy 0.9848 · Macro-F1 0.8141 · Weighted-F1 0.9863  
*Quick sanity run (small mixed sample):* Acc 0.9998 · Macro-F1 0.6664 · Weighted-F1 0.9998

## How it works
- **Input:** CICIDS2017 daily CSVs (Monday…Friday).
- **Prep:** select 37 flow features, clean infinities/NaN, write `data/processed/flows.csv`.
- **Model:** RandomForest (`n_estimators=400`, `class_weight=balanced_subsample`, `random_state=1`, `max_depth=100`).
- **Split:** 80/20, seed=1.  
- **Outputs:** `models/rf_model.pkl`, `models/meta.json`, and under `reports/`: `metrics.json`,
  `classification_report.txt`, `confusion_matrix_counts.png`, `confusion_matrix_normalized.png`.

## Quickstart
1) `python3 -m venv .venv`  
2) `source .venv/bin/activate`  (Windows: `.venv\Scripts\Activate.ps1`)  
3) `pip install -r requirements.txt`

## Dataset layout (no data in git)
```text
data/
  raw/
    CICIDS2017/
      Monday-WorkingHours.pcap_ISCX.csv
      Tuesday-WorkingHours.pcap_ISCX.csv
      Wednesday-workingHours.pcap_ISCX.csv
      Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
      Thursday-WorkingHours-Afternoon-Infiltration.pcap_ISCX.csv
      Friday-WorkingHours-Morning.pcap_ISCX.csv
      Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
      Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
  processed/
    flows.csv
Build / Train / Evaluate
bash
Copy code
python -m src.data_prep --raw-dir data/raw/CICIDS2017 --out data/processed/flows.csv
python -m src.train_rf --csv data/processed/flows.csv --random-state 1 --n-estimators 400 --max-depth 100 --class-weight balanced_subsample --out-model models/rf_model.pkl --out-meta models/meta.json --reports-dir reports
python -m src.eval_rf --csv data/processed/flows.csv --model models/rf_model.pkl --meta models/meta.json --reports-dir reports

## Thesis sketch
See [docs/thesis_sketch.md](docs/thesis_sketch.md)
