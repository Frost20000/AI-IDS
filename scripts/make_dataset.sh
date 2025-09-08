#!/usr/bin/env bash
set -euo pipefail
python -m src.data_prep \
  --raw-dir data/raw \
  --pattern "*.csv" \
  --out data/processed/cicids_train_flows.csv \
  --label-col Label
echo "[ok] data/processed/cicids_train_flows.csv"
