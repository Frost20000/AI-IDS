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

