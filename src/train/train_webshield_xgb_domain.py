import os
import joblib
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, roc_auc_score
import numpy as np

from src.features.url_features import extract_url_features
from src.train.domain_split import domain_based_split
from src.features.domain_utils import get_registered_domain

os.makedirs("models", exist_ok=True)

print("📦 Teknik Odaklı Model İçin Veri Yükleniyor...")
df = pd.read_csv("data/webshield_ready_for_model.csv")
df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)

# 1. DOMAIN TEMİZLİĞİ VE BÖLME
df["domain_tmp"] = df["url"].astype(str).apply(get_registered_domain)
bad = df["domain_tmp"].isna() | (df["domain_tmp"].astype(str).str.strip() == "")
if bad.sum() > 0:
    df = df[~bad].reset_index(drop=True)
df = df.drop(columns=["domain_tmp"])

print("⚖️ Veri Bölünüyor...")
train_df, test_df = domain_based_split(df, test_size=0.20, random_state=42)

y_train = train_df["label"].astype(int)
y_test = test_df["label"].astype(int)

# 2. LEXICAL (URL YAPISI) - NLP TAMAMEN KALDIRILDI
print("🔍 Lexical: URL yapısal özellikleri çıkarılıyor...")
X_train_lex = train_df["url"].astype(str).apply(lambda u: pd.Series(extract_url_features(u))).fillna(0).astype(float)
X_test_lex = test_df["url"].astype(str).apply(lambda u: pd.Series(extract_url_features(u))).fillna(0).astype(float)

# 3. OSINT (SİBER İSTİHBARAT)
print("🌍 OSINT: DNS kayıtları entegre ediliyor...")
osint_cols = ["has_mx_record", "has_spf_record", "dns_a_record_count", "txt_record_count", "mx_record_count"]
X_train_osint = train_df[osint_cols].fillna(0).astype(float)
X_test_osint = test_df[osint_cols].fillna(0).astype(float)

# 4. BİRLEŞTİRME (FUSION) - SADECE TEKNİK VE YAPISAL
# NLP (TF-IDF) verisi burada artık yer almıyor.
print("🧬 Teknik ve Yapısal beyinler birleştiriliyor (NLP Devre Dışı)...")

# DataFrame değerlerini numpy dizisine çevirip yatayda (axis=1) birleştiriyoruz
X_train_all = np.concatenate([X_train_lex.values, X_train_osint.values], axis=1)
X_test_all  = np.concatenate([X_test_lex.values, X_test_osint.values], axis=1)

# 5. MODEL EĞİTİMİ (XGBoost)
print("🚀 XGBoost Teknik Modda Eğitiliyor...")
model = xgb.XGBClassifier(
    n_estimators=400,
    max_depth=7,
    learning_rate=0.05,
    subsample=0.9,
    colsample_bytree=0.9,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_all, y_train)

# 6. DEĞERLENDİRME
y_pred = model.predict(X_test_all)
y_prob = model.predict_proba(X_test_all)[:, 1]

print("\n--- TEKNİK MODEL SONUÇLARI ---")
print(classification_report(y_test, y_pred, digits=4))
print("ROC-AUC Skoru:", round(roc_auc_score(y_test, y_prob), 4))

# TF-IDF dosyası artık oluşturulmuyor, sadece model kaydediliyor.
joblib.dump({"model": model}, "models/webshield_ultimate_model.pkl")
print("\n✅ Teknik Model Kaydedildi: models/webshield_ultimate_model.pkl")