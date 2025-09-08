#!/usr/bin/env python3
import argparse, json, os, pickle, gzip, bz2, lzma
import numpy as np, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
import matplotlib.pyplot as plt

# ---------- loading ----------
def load_model(path):
    # try joblib first
    try:
        import joblib
        return joblib.load(path)
    except Exception:
        pass
    # fall back to pickle (+ common compressions)
    for opener in (open, gzip.open, bz2.open, lzma.open):
        try:
            with opener(path, "rb") as f:
                return pickle.load(f)
        except Exception:
            continue
    raise RuntimeError(
        "Could not load model. Ensure joblib is installed and scikit-learn "
        "version is compatible with the model."
    )

# ---------- plotting ----------
def plot_cm(cm, labels, normalized, outpath):
    data = cm.astype(float)
    title = "Confusion Matrix (counts)"
    if normalized:
        rs = data.sum(axis=1, keepdims=True)
        rs[rs == 0] = 1.0
        data = data / rs
        title = "Confusion Matrix (row-normalized)"
    fig = plt.figure(figsize=(10, 8))
    ax = plt.gca()
    ax.imshow(data, interpolation="nearest")
    ax.set_title(title)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_xticks(range(len(labels))); ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels)
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            v = data[i, j]
            ax.text(j, i, f"{v:.0f}" if not normalized else f"{v*100:.1f}%",
                    ha="center", va="center")
    fig.tight_layout()
    fig.savefig(outpath, dpi=200)
    plt.close(fig)

# ---------- cleaning ----------
def sanitize_features(df, feat_cols, fill_strategy="median"):
    """
    Coerce to numeric, replace +/-inf with NaN, fill NaN, clip to float32 range.
    Returns cleaned numpy array (float32) and a small report.
    """
    rep = {}
    # to numeric (coerce weird strings)
    for c in feat_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    # replace infinities
    inf_before = np.isinf(df[feat_cols].to_numpy()).sum()
    df[feat_cols] = df[feat_cols].replace([np.inf, -np.inf], np.nan)
    # fill NaNs
    if fill_strategy == "median":
        med = df[feat_cols].median()
        df[feat_cols] = df[feat_cols].fillna(med)
    elif fill_strategy == "zero":
        df[feat_cols] = df[feat_cols].fillna(0.0)
    else:
        # default to median
        med = df[feat_cols].median()
        df[feat_cols] = df[feat_cols].fillna(med)
    # clip to float32 range
    f32_max = np.finfo(np.float32).max
    f32_min = -f32_max
    df[feat_cols] = df[feat_cols].clip(lower=f32_min, upper=f32_max)
    # report
    rep["infinities_replaced"] = int(inf_before)
    rep["nans_after_fill"] = int(df[feat_cols].isna().to_numpy().sum())
    X = df[feat_cols].to_numpy(dtype=np.float32, copy=False)
    return X, rep

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", help="cicids_train_flows.csv")
    ap.add_argument("--model", default="rf_flow_mc_new.pkl")
    ap.add_argument("--meta",  default="rf_flow_mc_new.meta.json")
    ap.add_argument("--outdir", default="cm_out")
    ap.add_argument("--fill", choices=["median","zero"], default="median",
                    help="how to fill NaN after replacing infinities")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    with open(args.meta, "r") as f:
        meta = json.load(f)
    model = load_model(args.model)

    feat_cols = meta.get("feature_names") or meta.get("feature_columns")
    if not feat_cols:
        raise RuntimeError("Meta missing feature_names/feature_columns.")
    label_col = meta.get("label_col", "Label")
    test_size = float(meta.get("test_size", 0.2))
    seed = int(meta.get("seed", 1))

    usecols = feat_cols + [label_col]
    df = pd.read_csv(args.csv, usecols=usecols)

    # clean X
    X_all, rep = sanitize_features(df.copy(), feat_cols, fill_strategy=args.fill)
    y_all = df[label_col].to_numpy()

    # same split as training
    Xtr, Xte, ytr, yte = train_test_split(
        X_all, y_all, test_size=test_size, random_state=seed, stratify=y_all
    )

    if rep["infinities_replaced"] or rep["nans_after_fill"]:
        print(f"[clean] infinities replaced: {rep['infinities_replaced']}, "
              f"nans after fill: {rep['nans_after_fill']}")

    # predict
    yhat = model.predict(Xte)

    # class order
    classes = list(getattr(model, "classes_", sorted(np.unique(y_all))))
    cm = confusion_matrix(yte, yhat, labels=classes)

    # save CSV + PNGs + report
    cm_df = pd.DataFrame(cm, index=classes, columns=classes)
    cm_df.to_csv(os.path.join(args.outdir, "confusion_matrix_counts.csv"))
    plot_cm(cm, classes, normalized=False,
            outpath=os.path.join(args.outdir, "confusion_matrix_counts.png"))
    plot_cm(cm, classes, normalized=True,
            outpath=os.path.join(args.outdir, "confusion_matrix_normalized.png"))

    rep_txt = classification_report(yte, yhat, labels=classes, zero_division=0)
    with open(os.path.join(args.outdir, "classification_report.txt"), "w") as f:
        f.write(rep_txt)

    print("Saved confusion matrix to:", args.outdir)

if __name__ == "__main__":
    main()
