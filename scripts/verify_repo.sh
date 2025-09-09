# scripts/verify_repo.sh
#!/usr/bin/env bash
set -u

pass=0; fail=0; skip=0
P() { printf "✅ PASS  %s\n" "$1"; pass=$((pass+1)); }
F() { printf "❌ FAIL  %s\n" "$1"; fail=$((fail+1)); }
S() { printf "➖ SKIP  %s\n" "$1"; skip=$((skip+1)); }

# 0) Basic repo sanity
git rev-parse --show-toplevel >/dev/null 2>&1 || { echo "Run inside a git repo."; exit 1; }
repo_root=$(git rev-parse --show-toplevel)

# 1) README sections & quickstart commands
sections=(
  "^## Overview"
  "^## Dataset"
  "^## Environment Setup"
  "^## Reproducible Training"
  "^## Evaluation"
  "^## How to Run"
  "^## Repository Structure"
  "^## Limitations"
  "^## Ethics"
)
missing=0
for s in "${sections[@]}"; do
  grep -qE "$s" README.md || { missing=1; }
done
if [ "$missing" = 0 ]; then P "README contains required sections"; else F "README missing one or more required sections"; fi

grep -q "python -m venv .venv" README.md && grep -q "pip install -r requirements.txt" README.md \
  && P "README quickstart shows venv + pip install" \
  || F "README quickstart missing venv/pip lines"

# 2) Requirements pinned
req_ok=1
grep -qE '^numpy==[0-9]+\.' requirements.txt || req_ok=0
grep -qE '^pandas==[0-9]+\.' requirements.txt || req_ok=0
grep -qE '^scikit-learn==[0-9]+\.' requirements.txt || req_ok=0
grep -qE '^matplotlib==[0-9]+\.' requirements.txt || req_ok=0
grep -qE '^tqdm==[0-9]+\.' requirements.txt || req_ok=0
grep -qE '^joblib==[0-9]+\.' requirements.txt || req_ok=0
grep -qE '^scapy==[0-9]+\.' requirements.txt || req_ok=0
[ "$req_ok" = 1 ] && P "requirements.txt uses pinned versions" || F "requirements.txt not pinned as required"

# 3) Scripts exist + executable
for s in scripts/make_dataset.sh scripts/train.sh scripts/evaluate.sh; do
  if [ -f "$s" ]; then
    [ -x "$s" ] && P "$s is executable" || { F "$s exists but is not executable"; }
  else
    F "$s missing"
  fi
done

# 4) Source files present
src_ok=1
for f in src/data_prep.py src/train_rf.py src/eval_rf.py src/utils.py src/live_demo_stub.py; do
  [ -f "$f" ] || { src_ok=0; echo "   missing: $f"; }
done
[ "$src_ok" = 1 ] && P "All src files present" || F "One or more src files are missing"

# 5) .gitignore rules
gi_ok=1
grep -qE '^data/\*\*' .gitignore || gi_ok=0
grep -qE '^models/\*\*' .gitignore || gi_ok=0
grep -qE '^\.venv/' .gitignore || gi_ok=0
grep -qE '^__pycache__/' .gitignore || gi_ok=0
[ "$gi_ok" = 1 ] && P ".gitignore covers data/, models/, venv, __pycache__" || F ".gitignore missing some rules"

# 6) No raw data tracked
tracked_bad=$(git ls-files | grep -E '(^|/)(datasets 2017|data/raw|\.pcap(\.ISCX\.csv)?)' || true)
[ -z "$tracked_bad" ] && P "No raw data tracked in git" || F "Raw data appears tracked:\n$tracked_bad"

# 7) Example reports present
have_reports=1
for r in reports/metrics.json reports/confusion_matrix_counts.png reports/confusion_matrix_normalized.png reports/classification_report.txt; do
  [ -f "$r" ] || have_reports=0
done
[ "$have_reports" = 1 ] && P "Reports present (JSON + PNGs + TXT)" || F "Missing one or more report artifacts"

# 8) Model & meta LOCAL but not tracked
if [ -f models/rf_model.pkl ] && [ -f models/meta.json ]; then
  # If tracked, ls-files will print them; we expect nothing (ignored or simply not added)
  t=$(git ls-files -- models/rf_model.pkl models/meta.json || true)
  [ -z "$t" ] && P "Model+meta exist locally and are not tracked" || F "models/* artifacts are tracked; should not be"
else
  S "models/rf_model.pkl + models/meta.json not present locally (ok if you didn’t train here)"
fi

# 9) Tone audit (no hype)
if grep -qiE 'cutting[- ]edge|holistic|revolutionary|synerg|paradigm|state[- ]of[- ]the[- ]art|we delve' README.md; then
  F "Hype words found in README"
else
  P "Tone audit (README) clean"
fi

# 10) CLI wiring check (help text runs)
py_ok=1
python - <<'PY' >/dev/null 2>&1 || py_ok=0
import importlib, sys
for m in ("src.data_prep","src.train_rf","src.eval_rf"):
    importlib.import_module(m)
PY
[ "$py_ok" = 1 ] && P "Python modules importable" || F "Python module import error"

# 11) Optional: run evaluator if inputs exist
if [ -f data/processed/flows.csv ] && [ -f models/rf_model.pkl ] && [ -f models/meta.json ]; then
  if python -m src.eval_rf --csv data/processed/flows.csv --label-col Label --model models/rf_model.pkl --meta models/meta.json --reports-dir reports >/dev/null 2>&1; then
    P "Evaluator ran end-to-end (repo model)"
  else
    F "Evaluator failed to run (repo model)"
  fi
else
  S "Evaluator run skipped (need data/processed/flows.csv and repo model)"
fi

# 12) Optional: gh release presence (v1.0 or v1.1)
if command -v gh >/dev/null 2>&1; then
  if gh release view v1.1 >/dev/null 2>&1 || gh release view v1.0 >/dev/null 2>&1; then
    P "GitHub release present (v1.0 and/or v1.1)"
  else
    S "No GitHub release found (optional)"
  fi
else
  S "gh CLI not installed; skip release check"
fi

echo "-------------------------------------------"
printf "Summary: %s pass, %s fail, %s skip\n" "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ] && { echo "ALL GREEN ✅"; exit 0; } || { echo "SOME CHECKS FAILED ❌"; exit 1; }
