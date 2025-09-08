import argparse, os, json, joblib, numpy as np, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from .utils import ensure_dir, compute_metrics, save_confusion_artifacts

def main():
    ap = argparse.ArgumentParser(description="Evaluate RandomForest on deterministic split")
    ap.add_argument("--csv", default="data/processed/cicids_train_flows.csv")
    ap.add_argument("--label-col", default="Label")
    ap.add_argument("--model", default="models/rf_model.pkl")
    ap.add_argument("--meta", default="models/meta.json")
    ap.add_argument("--reports-dir", default="reports")
    ap.add_argument("--random-state", type=int, default=1)
    args = ap.parse_args()

    ensure_dir(args.reports_dir)
    meta = json.load(open(args.meta, "r", encoding="utf-8"))
    feats = meta.get("feature_names"); classes = meta.get("classes")
    test_size = float(meta.get("test_size", 0.2)); seed = int(meta.get("seed", args.random_state))

    df = pd.read_csv(args.csv, usecols=feats + [args.label_col])
    X = df[feats].to_numpy(np.float32); y = df[args.label_col].to_numpy()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=test_size, random_state=seed, stratify=y)

    clf = joblib.load(args.model); yhat = clf.predict(Xte)
    m = compute_metrics(yte, yhat)
    print(f"Accuracy     : {m.accuracy:.4f}")
    print(f"Macro-F1     : {m.macro_f1:.4f}")
    print(f"Weighted-F1  : {m.weighted_f1:.4f}")

    if not classes: classes = sorted(list(set(yte)))
    save_confusion_artifacts(yte, yhat, classes, args.reports_dir)

    rep = classification_report(yte, yhat, labels=classes, zero_division=0)
    with open(os.path.join(args.reports_dir,"classification_report.txt"),"w",encoding="utf-8") as f: f.write(rep)
    print("[done] evaluation complete")
if __name__ == "__main__": main()
