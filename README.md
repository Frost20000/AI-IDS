# AI-IDS (CICIDS2017, RandomForest)

Flow-based IDS on CICIDS2017 using a multiclass RandomForest.
Training and evaluation are reproducible. A small demo stub is in `src/live_demo_stub.py` (no packet capture).

## Results (thesis run)
Accuracy: 0.9848
Macro-F1: 0.8141
Weighted-F1: 0.9863

Quick sanity run (small mixed sample):
Acc 0.9998 · Macro-F1 0.6664 · Weighted-F1 0.9998

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
    flows.csv

## Build flows.csv
python -m src.data_prep --raw-dir data/raw/CICIDS2017 --out data/processed/flows.csv

## Train
python -m src.train_rf --csv data/processed/flows.csv --random-state 1 --n-estimators 400 --max-depth 100 --class-weight balanced_subsample --out-model models/rf_model.pkl --out-meta models/meta.json --reports-dir reports

## Evaluate
python -m src.eval_rf --csv data/processed/flows.csv --model models/rf_model.pkl --meta models/meta.json --reports-dir reports

## Artifacts (in reports/)
- metrics.json
- classification_report.txt
- confusion_matrix_counts.png
- confusion_matrix_normalized.png

Notes:
- Keep data/ and models/ out of git (.gitignore handles this).
