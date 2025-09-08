import argparse, glob, os, pandas as pd
from .utils import ensure_dir
DEFAULT_LABEL = "Label"
def main():
    ap = argparse.ArgumentParser(description="Merge CICIDS2017 flow CSVs")
    ap.add_argument("--raw-dir", default="data/raw")
    ap.add_argument("--pattern", default="*.csv")
    ap.add_argument("--out", default="data/processed/cicids_train_flows.csv")
    ap.add_argument("--label-col", default=DEFAULT_LABEL)
    args = ap.parse_args()
    ensure_dir(os.path.dirname(args.out) or ".")
    files = sorted(glob.glob(os.path.join(args.raw_dir, args.pattern)))
    if not files: raise SystemExit(f"No CSVs in {args.raw_dir}")
    df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
    if args.label_col not in df.columns: raise SystemExit(f"Missing label '{args.label_col}'")
    # Keep numeric features + label
    feats = [c for c in df.select_dtypes(include=["number"]).columns if c != args.label_col]
    df = df[feats + [args.label_col]]
    # Basic clean
    for c in feats: df[c] = pd.to_numeric(df[c], errors="coerce")
    df[feats] = df[feats].fillna(df[feats].median())
    df.to_csv(args.out, index=False)
    print(f"[saved] {args.out} ({len(df)} rows, {len(feats)} features + label)")
if __name__ == "__main__": main()
