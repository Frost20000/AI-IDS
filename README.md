# AI-IDS (CICIDS2017 · RandomForest)

Flow-based IDS on CICIDS2017 using a multiclass RandomForest.
Reproducible training and evaluation. A simple live-demo stub is included (no packet capture).

See **README_handoff.md** for a short pre-defense checklist.

## Results (thesis run)
- Accuracy: **0.9848**
- Macro-F1: **0.8141**
- Weighted-F1: **0.9863**

*Sanity run on a small mixed sample (quick check):* Acc **0.9998** · Macro-F1 **0.6664** · Weighted-F1 **0.9998** (imbalanced sample).

Figures:  
- Normalized confusion matrix → `reports/confusion_matrix_normalized.png`  
- Counts confusion matrix → `reports/confusion_matrix_counts.png`  
- Classification report → `reports/classification_report.txt`

## Quickstart
```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
