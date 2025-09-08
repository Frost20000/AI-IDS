#!/usr/bin/env bash
set -euo pipefail
python -m src.train_rf \
  --csv data/processed/cicids_train_flows.csv \
  --label-col Label \
  --out-model models/rf_model.pkl \
  --out-meta models/meta.json
echo "[ok] model + meta saved under models/"
