import argparse, os, joblib, pandas as pd
from sklearn.model_selection import train_test_split

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--random-state", type=int, default=1)
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--out-model", default="models/boost_model.pkl")
    ap.add_argument("--reports-dir", default="reports")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out_model), exist_ok=True)
    os.makedirs(args.reports_dir, exist_ok=True)

    df = pd.read_csv(args.csv)
    X = df.drop(columns=["Label"])
    y = df["Label"]

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=args.test_size, random_state=args.random_state, stratify=y)

    model = None
    try:
        from xgboost import XGBClassifier
        model = XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.1,
            subsample=0.9, colsample_bytree=0.9, eval_metric="mlogloss",
            tree_method="hist", random_state=args.random_state
        )
        name = "xgboost"
    except Exception:
        from sklearn.ensemble import HistGradientBoostingClassifier
        model = HistGradientBoostingClassifier(max_depth=8, random_state=args.random_state)
        name = "sklearn-hgb"

    model.fit(Xtr, ytr)
    joblib.dump(model, args.out_model)
    print(f"[ok] saved {args.out_model} ({name})")

    # quick eval
    from sklearn.metrics import accuracy_score, f1_score
    ypred = model.predict(Xte)
    acc = accuracy_score(yte, ypred)
    f1m = f1_score(yte, ypred, average="macro")
    f1w = f1_score(yte, ypred, average="weighted")
    with open(os.path.join(args.reports_dir,"baseline_boost.txt"),"w") as f:
        f.write(f"model={name}\naccuracy={acc:.4f}\nmacro_f1={f1m:.4f}\nweighted_f1={f1w:.4f}\n")
    print("[ok] baseline_boost.txt written")

if __name__ == "__main__":
    main()
