import joblib
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt

from sklearn.metrics import roc_curve, auc
from scipy.sparse import hstack

from src.train.domain_split import domain_based_split
from src.features.url_features import extract_url_features

# -----------------------------------
# MODEL & DATA LOAD
# -----------------------------------
bundle = joblib.load("models/webshield_xgb_domain.pkl")
model = bundle["model"]
tfidf = bundle["tfidf"]

df = pd.read_csv("data/raw_urls.csv")

# -----------------------------------
# DOMAIN-BASED SPLIT
# -----------------------------------
train_df, test_df = domain_based_split(df, test_size=0.2, random_state=42)

X_test_text = test_df["url"].astype(str)
y_test = test_df["label"].astype(int)

X_test_tfidf = tfidf.transform(X_test_text)

X_test_num = X_test_text.apply(
    lambda u: pd.Series(extract_url_features(u))
).fillna(0).astype(float)

X_test_all = hstack([X_test_tfidf, X_test_num.values])

# -----------------------------------
# RISK SKORU
# -----------------------------------
y_proba = model.predict_proba(X_test_all)[:, 1]

# -----------------------------------
# ROC CURVE
# -----------------------------------
fpr, tpr, thresholds = roc_curve(y_test, y_proba)
roc_auc = auc(fpr, tpr)

plt.figure(figsize=(6,5))
plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.4f}")
plt.plot([0,1], [0,1], linestyle="--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate (Recall)")
plt.title("WebShield ROC Curve (Domain-based)")
plt.legend() 
plt.tight_layout()
plt.show()

# -----------------------------------
# THRESHOLD ANALYSIS
# -----------------------------------
def evaluate_threshold(th):
    preds = (y_proba >= th).astype(int)
    tp = ((preds == 1) & (y_test == 1)).sum()
    fp = ((preds == 1) & (y_test == 0)).sum()
    fn = ((preds == 0) & (y_test == 1)).sum()
    recall = tp / (tp + fn + 1e-9)
    precision = tp / (tp + fp + 1e-9)
    return precision, recall, fp, fn

for th in [0.3, 0.4, 0.5, 0.6, 0.7]:
    p, r, fp, fn = evaluate_threshold(th)
    print(f"Threshold={th:.2f} | Precision={p:.4f} | Recall={r:.4f} | FP={fp} | FN={fn}")
