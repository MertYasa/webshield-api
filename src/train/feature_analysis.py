# src/train/feature_analysis.py
import joblib
import matplotlib.pyplot as plt

# 1. Özellik isimlerini modelin eğitim sırasına göre tam listeliyoruz
lexical_features = [
    "url_length", "domain_length", "path_length", "has_ip",
    "count_at", "count_dash", "count_dot", "count_slash",
    "count_equals", "digit_ratio", "has_https", "subdomain_count",
    "is_suspicious_tld", "has_embedded_domain", "has_phishing_keyword"
]

osint_features = [
    "has_mx_record", "has_spf_record", "dns_a_record_count", 
    "txt_record_count", "mx_record_count"
]

# Tüm özelliklerin birleşimi (Eğitimdeki sırayla birebir aynı olmalı)
feature_names = lexical_features + osint_features

print("📦 Model yükleniyor...")
bundle = joblib.load("models/webshield_ultimate_model.pkl")
model = bundle["model"]

# 2. XGBoost'un "Feature Importance" (Özellik Önemi) değerlerini çekiyoruz
importances = model.feature_importances_

# 3. İsimler ve skorları eşleştirip, en önemliden en önemsize doğru sıralıyoruz
feature_importance_dict = dict(zip(feature_names, importances))
sorted_features = sorted(feature_importance_dict.items(), key=lambda x: x[1], reverse=True)

# 4. Terminale Raporlama
print("\n🧠 XGBoost Modelinin En Çok Değer Verdiği Özellikler:\n" + "-"*50)
for name, score in sorted_features:
    print(f"{name.ljust(25)}: %{score * 100:.2f}")

# 5. Görselleştirme (Matplotlib ile bar grafiği)
# Sadece en önemli ilk 10 özelliği çizdirelim
top_10_features = [x[0] for x in sorted_features[:10]]
top_10_scores = [x[1] * 100 for x in sorted_features[:10]]

plt.figure(figsize=(10, 6))
# Grafiği yukarıdan aşağıya doğru sıralı çizmek için listeleri tersine çeviriyoruz [::-1]
plt.barh(top_10_features[::-1], top_10_scores[::-1], color='#3b82f6', edgecolor='black')
plt.xlabel('Önem Oranı (Model Kararındaki Etkisi %)')
plt.title('WebShield: XGBoost Karar Ağacı Özellik Ağırlıkları (Top 10)')
plt.grid(axis='x', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.show()