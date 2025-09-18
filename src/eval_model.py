import argparse, os, json
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import joblib

def evaluate(csv, model_path, reports_dir, label_col="Label"):
    os.makedirs(reports_dir, exist_ok=True)
    print(f"[i] Loading {csv}")
    df = pd.read_csv(csv)
    X = df.drop(columns=[label_col])
    y = df[label_col]

    print(f"[i] Loading model: {model_path}")
    model = joblib.load(model_path)

    print("[i] Predicting...")
    y_pred = model.predict(X)

    acc = float(accuracy_score(y, y_pred))
    f1_macro = float(f1_score(y, y_pred, average='macro'))
    f1_weighted = float(f1_score(y, y_pred, average='weighted'))

    metrics = {"accuracy": acc, "macro_f1": f1_macro, "weighted_f1": f1_weighted}
    with open(os.path.join(reports_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    print("[ok] metrics.json written")

    # classification report
    cr = classification_report(y, y_pred)
    with open(os.path.join(reports_dir, "classification_report.txt"), "w") as f:
        f.write(cr)
    print("[ok] classification_report.txt written")

    # confusion matrices
    labels = sorted(list(set(y)))
    cm = confusion_matrix(y, y_pred, labels=labels)
    fig = plt.figure()
    plt.imshow(cm, interpolation='nearest')
    plt.title("Confusion Matrix (counts)")
    plt.xticks(range(len(labels)), labels, rotation=90)
    plt.yticks(range(len(labels)), labels)
    plt.tight_layout()
    fig.savefig(os.path.join(reports_dir, "confusion_matrix_counts.png"))
    plt.close(fig)

    cm_norm = cm.astype("float") / (cm.sum(axis=1, keepdims=True) + 1e-12)
    fig2 = plt.figure()
    plt.imshow(cm_norm, interpolation='nearest')
    plt.title("Confusion Matrix (normalized)")
    plt.xticks(range(len(labels)), labels, rotation=90)
    plt.yticks(range(len(labels)), labels)
    plt.tight_layout()
    fig2.savefig(os.path.join(reports_dir, "confusion_matrix_normalized.png"))
    plt.close(fig2)
    print("[ok] confusion matrices written")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--reports-dir", required=True)
    args = ap.parse_args()
    evaluate(args.csv, args.model, args.reports_dir)
