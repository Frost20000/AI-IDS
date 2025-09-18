import argparse, os, pandas as pd, joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
try:
    from xgboost import XGBClassifier
    HAS_XGB=True
except Exception:
    from sklearn.ensemble import HistGradientBoostingClassifier
    HAS_XGB=False

def metric_row(name, y_true, y_pred):
    return dict(
        model=name,
        accuracy=accuracy_score(y_true, y_pred),
        macro_f1=f1_score(y_true, y_pred, average='macro'),
        weighted_f1=f1_score(y_true, y_pred, average='weighted')
    )

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--random-state", type=int, default=1)
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--reports-dir", default="reports")
    args=ap.parse_args()
    os.makedirs(args.reports_dir, exist_ok=True)

    df=pd.read_csv(args.csv)
    X=df.drop(columns=["Label"]); y=df["Label"]
    Xtr,Xte,ytr,yte = train_test_split(X,y,test_size=args.test_size,stratify=y,random_state=args.random_state)

    results=[]

    # Logistic Regression
    logreg = Pipeline([("scaler", StandardScaler(with_mean=False)), ("clf", LogisticRegression(max_iter=1000))])
    logreg.fit(Xtr,ytr)
    results.append(metric_row("LogReg", yte, logreg.predict(Xte)))

    # RandomForest (same settings you report)
    rf = RandomForestClassifier(n_estimators=400, max_depth=100, class_weight="balanced_subsample", random_state=args.random_state, n_jobs=-1)
    rf.fit(Xtr,ytr)
    results.append(metric_row("RandomForest", yte, rf.predict(Xte)))

    # Booster
    if HAS_XGB:
        booster = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.9, colsample_bytree=0.9, eval_metric="mlogloss", tree_method="hist", random_state=args.random_state)
        name="XGBoost"
    else:
        booster = HistGradientBoostingClassifier(max_depth=8, random_state=args.random_state)
        name="HistGradientBoosting"
    booster.fit(Xtr,ytr)
    results.append(metric_row(name, yte, booster.predict(Xte)))

    out_csv=os.path.join(args.reports_dir,"benchmarks.csv")
    out_md =os.path.join(args.reports_dir,"benchmarks.md")
    dfres = pd.DataFrame(results).sort_values("macro_f1", ascending=False)
    dfres.to_csv(out_csv, index=False)
    with open(out_md,"w") as f:
        f.write(dfres.to_markdown(index=False))
    print(f"[ok] wrote {out_csv} and {out_md}")

if __name__=="__main__":
    main()
