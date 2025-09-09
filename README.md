# AI-IDS
Flow-based IDS on CICIDS2017 using a multiclass RandomForest.
Reproducible training, evaluation, and a simple live-demo stub.

See README_handoff.md for a quick test checklist.

## Results (thesis run)

- Accuracy: **0.9848**
- Macro-F1: **0.8141**
- Weighted-F1: **0.9863**

Figures: [normalized matrix](reports/confusion_matrix_normalized.png), [counts](reports/confusion_matrix_counts.png), [classification report](reports/classification_report.txt).


## Confusion matrix (row-normalized)
![](reports/confusion_matrix_normalized.png)

## Optional: evaluate an external pre-trained model

If you have a model saved with a newer scikit-learn (e.g., the GUI model):

```bash
python -m venv .evalvenv
source .evalvenv/bin/activate
pip install 'scikit-learn>=1.7.1,<1.8' numpy pandas matplotlib joblib scipy

python src/eval_rf.py \
  --csv data/processed/flows.csv \
  --label-col Label \
  --model rf_flow_mc.pkl \
  --meta rf_flow_mc.meta.json \
  --reports-dir reports


## Overview
Flow-based IDS on CICIDS2017 using a multiclass RandomForest. Reproducible training and evaluation. A simple live-demo stub is included (no packet capture by default).

## Dataset
Place the original CICIDS2017 daily CSVs under:


## Overview
Flow-based IDS on CICIDS2017 using a multiclass RandomForest. Reproducible training and evaluation. A simple live-demo stub is included (no packet capture by default).

## Dataset
Place the original CICIDS2017 daily CSVs under:

## Dataset layout

Place the original CICIDS2017 daily CSVs here (no data in git):

data/
raw/
CICIDS2017/
Monday-WorkingHours.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
Wednesday-workingHours.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
Friday-WorkingHours-Morning.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
processed/
flows.csv # produced by src.data_prep
md
## Dataset layout

Place the original CICIDS2017 daily CSVs here (no data in git):

data/
raw/
CICIDS2017/
Monday-WorkingHours.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
Wednesday-workingHours.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
Friday-WorkingHours-Morning.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
processed/
flows.csv # produced by src.data_prep


## Dataset layout

Place the original CICIDS2017 daily CSVs here (no data in git):


data/
raw/
CICIDS2017/
Monday-WorkingHours.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
Wednesday-workingHours.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
Friday-WorkingHours-Morning.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
processed/
flows.csv # produced by src.data_prep

## Dataset layout

Place the original CICIDS2017 daily CSVs here (no data in git):

data/
raw/
CICIDS2017/
Monday-WorkingHours.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
Wednesday-workingHours.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
Friday-WorkingHours-Morning.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
processed/
flows.csv # produced by src.data_prep
