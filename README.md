# AI-IDS (CICIDS2017 · RandomForest)

Flow-based IDS on CICIDS2017 using a multiclass RandomForest.
Reproducible training and evaluation. Live-demo stub included (no packet capture).

## Results (thesis run)
Accuracy: 0.9848
Macro-F1: 0.8141
Weighted-F1: 0.9863

Quick sanity run (small mixed sample):
Acc 0.9998 · Macro-F1 0.6664 · Weighted-F1 0.9998 (imbalanced sample)

Figures (in reports/):
- confusion_matrix_normalized.png
- confusion_matrix_counts.png
- classification_report.txt
- metrics.json

## Quickstart
1) python3 -m venv .venv
2) source .venv/bin/activate    (Windows: .venv\Scripts\Activate.ps1)
3) pip install -r requirements.txt

## Dataset layout (no data in git)
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
    flows.csv   (written by data_prep)

## Build flows.csv
python -m src.data_prep --raw-dir data/raw/CICIDS2017 --out data/processed/flows.csv

## Train
python -m src.train_rf --csv data/processed/flows.csv --random-state 1 --n-estimators 400 --max-depth 100 --class-weight balanced_subsample --out-model models/rf_model.pkl --out-meta models/meta.json --reports-dir reports

## Evaluate
python -m src.eval_rf --csv data/processed/flows.csv --model models/rf_model.pkl --meta models/meta.json --reports-dir reports

Notes:
- Keep data/ and models/ out of git (.gitignore already handles this).
- See README_handoff.md for a short pre-defense checklist.
