import json, os, random
from dataclasses import dataclass
from typing import Dict, List
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

SEED = 1
def set_global_seed(seed: int = SEED) -> None:
    random.seed(seed); np.random.seed(seed)
def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)
@dataclass
class Metrics: accuracy: float; macro_f1: float; weighted_f1: float
def compute_metrics(y_true, y_pred) -> Metrics:
    from sklearn.metrics import f1_score, accuracy_score
    return Metrics(
        accuracy=accuracy_score(y_true, y_pred),
        macro_f1=f1_score(y_true, y_pred, average='macro', zero_division=0),
        weighted_f1=f1_score(y_true, y_pred, average='weighted', zero_division=0),
    )
def save_json(obj: Dict, path: str) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8") as f: json.dump(obj, f, indent=2)
def save_confusion_artifacts(y_true, y_pred, classes: List[str], reports_dir: str) -> None:
    import pandas as pd, matplotlib.pyplot as plt
    cm = confusion_matrix(y_true, y_pred, labels=classes)
    df = pd.DataFrame(cm, index=classes, columns=classes)
    p_csv = f"{reports_dir}/confusion_matrix_counts.csv"; df.to_csv(p_csv); print(f"[saved] {p_csv}")
    fig = plt.figure(figsize=(10,8)); ax=fig.gca(); ax.imshow(cm, interpolation="nearest")
    ax.set_title("Confusion Matrix (counts)"); ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    ax.set_xticks(range(len(classes))); ax.set_xticklabels(classes, rotation=45, ha="right")
    ax.set_yticks(range(len(classes))); ax.set_yticklabels(classes)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]): ax.text(j,i,f"{cm[i,j]:.0f}",ha="center",va="center")
    fig.tight_layout(); p1=f"{reports_dir}/confusion_matrix_counts.png"; fig.savefig(p1,dpi=200); plt.close(fig); print(f"[saved] {p1}")
    cmr = cm.astype(float); rs = cmr.sum(axis=1, keepdims=True); rs[rs==0]=1.0; cmr = cmr/rs
    fig = plt.figure(figsize=(10,8)); ax=fig.gca(); ax.imshow(cmr, interpolation="nearest")
    ax.set_title("Confusion Matrix (row-normalized)"); ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    ax.set_xticks(range(len(classes))); ax.set_xticklabels(classes, rotation=45, ha="right")
    ax.set_yticks(range(len(classes))); ax.set_yticklabels(classes)
    for i in range(cmr.shape[0]):
        for j in range(cmr.shape[1]): ax.text(j,i,f"{(cmr[i,j]*100):.1f}%",ha="center",va="center")
    fig.tight_layout(); p2=f"{reports_dir}/confusion_matrix_normalized.png"; fig.savefig(p2,dpi=200); plt.close(fig); print(f"[saved] {p2}")
