#!/usr/bin/env bash
set -euo pipefail
python -m src.eval_rf \
  --csv data/processed/cicids_train_flows.csv \
  --label-col Label \
  --model models/rf_model.pkl \
  --meta models/meta.json \
  --reports-dir reports
echo "[ok] reports written under reports/"
