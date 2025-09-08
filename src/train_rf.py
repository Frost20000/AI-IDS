import argparse, os, json, joblib, numpy as np, pandas as pd, sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from .utils import ensure_dir, compute_metrics

def main():
    ap = argparse.ArgumentParser(description="Train RandomForest on CICIDS2017 flows")
    ap.add_argument("--csv", default="data/processed/cicids_train_flows.csv")
    ap.add_argument("--label-col", default="Label")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--random-state", type=int, default=1)
    ap.add_argument("--n-estimators", type=int, default=400)
    ap.add_argument("--max-depth", type=int, default=None)
    ap.add_argument("--class-weight", default="balanced_subsample")
    ap.add_argument("--out-model", default="models/rf_model.pkl")
    ap.add_argument("--out-meta", default="models/meta.json")
    ap.add_argument("--reports-dir", default="reports")
    args = ap.parse_args()

    for p in (os.path.dirname(args.out_model), os.path.dirname(args.out_meta), args.reports_dir):
        if p: ensure_dir(p)

    df = pd.read_csv(args.csv)
    if args.label_col not in df.columns: raise SystemExit(f"Label '{args.label_col}' not in CSV")
    feats = [c for c in df.columns if c != args.label_col]
    X = df[feats].to_numpy(np.float32); y = df[args.label_col].to_numpy()

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=args.test_size, random_state=args.random_state, stratify=y)
    clf = RandomForestClassifier(n_estimators=args.n_estimators, max_depth=args.max_depth,
                                 class_weight=args.class_weight, random_state=args.random_state, n_jobs=-1)
    clf.fit(Xtr, ytr); yhat = clf.predict(Xte)

    m = compute_metrics(yte, yhat)
    print(f"Accuracy     : {m.accuracy:.4f}")
    print(f"Macro-F1     : {m.macro_f1:.4f}")
    print(f"Weighted-F1  : {m.weighted_f1:.4f}")

    joblib.dump(clf, args.out_model); print(f"[saved] {args.out_model}")
    meta = {"feature_names": feats, "label_col": args.label_col, "classes": list(getattr(clf,'classes_',[])),
            "test_size": args.test_size, "seed": args.random_state, "sklearn_version": sklearn.__version__}
    with open(args.out_meta, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2); print(f"[saved] {args.out_meta}")

if __name__ == "__main__": main()
