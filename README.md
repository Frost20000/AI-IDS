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
## Troubleshooting (pandas error)

If you see ModuleNotFoundError: No module named 'pandas', your virtualenv isn’t active or requirements weren’t installed.
### Run:

`python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`


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

# GUI (flow IDS demo)

A simple Tkinter/Scapy GUI for live sniffing or CSV replay with the trained model.

Location: scripts/live_ids_gui_flow_mc.py
Purpose: demo only (teaching/inspection). Not production-hardened.

## Requirements

pip install scapy

Linux/macOS: may need python3-tk (e.g., sudo apt-get install python3-tk).

Windows: install Npcap (packet capture driver).

Live sniffing usually needs admin privileges (Linux/macOS: sudo; Windows: run as Administrator).

## Model & meta

The GUI has a “Load Model + Meta” button. Click it and select your trained files:

models/rf_model.pkl

models/meta.json

(Optional) If you keep rf_flow_mc.pkl / rf_flow_mc.meta.json next to the script, it will try to auto-load them at start.

# Run
## Linux
sudo -E $(which python) scripts/live_ids_gui_flow_mc.py

## macOS
sudo python3 scripts/live_ids_gui_flow_mc.py

## Windows (PowerShell, as Administrator)
python scripts\live_ids_gui_flow_mc.py

## Using the app

Click Load Model + Meta (pick your models/rf_model.pkl and models/meta.json).

Choose a network interface (for live mode) and click Start Live Monitoring, or click Replay Traffic (CSV) to play a packet-level CSV.

Predictions and heuristic alerts (PortScan/DDoS) stream in the log window. Click Stop Monitoring to print a brief per-flow summary.

## CSV replay schema (required columns):
src_ip, dst_ip, protocol, time_to_live, src_port, dst_port, tcp_flags, seq_num, ack_num, window_size, packet_size

## Notes / Troubleshooting

ModuleNotFoundError: scapy → pip install scapy.

PermissionError on sniff → run with sudo / Administrator.

“No interface found” → run with privileges or ensure a pcap driver (Npcap) is installed (Windows).

Feature warnings in the log mean a feature isn’t computed live; it’s zero-filled (by design for the demo).

## Data integrity check

python scripts/validate_data.py --raw-dir data/raw/CICIDS2017 --flows data/processed/flows.csv
This confirms the 8 files are present, header/schema (incl. Label) are correct, prints per-class counts, and writes checksums to reports/checksums.txt.

## Baselines & Benchmark

## Baselines (train quickly on the same split)
python -m src.train_logreg --csv data/processed/flows.csv --reports-dir reports
python -m src.train_xgb_or_hgb --csv data/processed/flows.csv --reports-dir reports

## One-shot benchmark table (LogReg vs RF vs XGBoost/HGB)
python -m src.benchmark --csv data/processed/flows.csv --reports-dir reports
#### reports/benchmarks.csv and reports/benchmarks.md
## Benchmarks (RF vs baseline)
After training RF and the baseline, see reports/benchmarks.md for a comparison table.
Artifacts for the baseline are saved as metrics_logreg.json and confusion matrices with the logreg_ prefix.

## GUI (flow IDS demo)

A simple Tkinter/Scapy GUI for live sniffing or CSV replay with the trained model.

* Location: scripts/live_ids_gui_flow_mc.py

* Purpose: demo only (teaching/inspection). Not production-hardened.

## Requirements
pip install scapy


* Linux/macOS: may need python3-tk (e.g., sudo apt-get install python3-tk).

* Windows: install Npcap (packet capture driver).

* Live sniffing usually needs admin privileges (Linux/macOS: sudo; Windows: run PowerShell “as Administrator”).

## Model & meta

The GUI has a “Load Model + Meta” button. Click it and select your trained files:

models/rf_model.pkl

models/meta.json

(Optional) If you keep rf_flow_mc.pkl / rf_flow_mc.meta.json next to the script, it will try to auto-load them at start.

### Run

#### Linux

sudo -E $(which python) scripts/live_ids_gui_flow_mc.py


#### macOS

sudo python3 scripts/live_ids_gui_flow_mc.py


#### Windows (PowerShell, as Administrator)

python scripts\live_ids_gui_flow_mc.py

## Using the app

Click Load Model + Meta (pick models/rf_model.pkl and models/meta.json).

Choose a network interface and click Start Live Monitoring, or click Replay Traffic (CSV) to play a packet-level CSV.

Predictions and heuristic alerts (PortScan/DDoS) stream in the log window. Click Stop Monitoring for a brief per-flow summary.

## CSV replay (required columns):
src_ip, dst_ip, protocol, time_to_live, src_port, dst_port, tcp_flags, seq_num, ack_num, window_size, packet_size

## Notes / Troubleshooting

ModuleNotFoundError: scapy → pip install scapy.

PermissionError on sniff → run with sudo / as Administrator.

“No interface found” → ensure privileges and a capture driver (Npcap on Windows).

Feature warnings in the log mean a feature isn’t computed live; it’s zero-filled (by design for the demo).

## Data integrity check
python scripts/validate_data.py --raw-dir data/raw/CICIDS2017 --flows data/processed/flows.csv


This confirms the 8 files are present, header/schema (incl. Label) are correct, prints per-class counts, and writes checksums to reports/checksums.txt.

## Notes

Data files are not tracked in git; folders may include .gitkeep to preserve structure.

The GUI is an instructional demo. The core deliverable is a clean, reproducible pipeline with saved artifacts.
