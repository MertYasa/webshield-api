import pandas as pd

# Girdi dosyaları
FILES = [
    "data/urlhaus_urls.csv",
    "data/openphish_urls.csv",
    "data/tranco_legit_urls.csv"
]

dfs = []
for f in FILES:
    df = pd.read_csv(f)
    dfs.append(df)

# Birleştir
df_all = pd.concat(dfs, ignore_index=True)

# Karıştır (bias olmasın)
df_all = df_all.sample(frac=1, random_state=42).reset_index(drop=True)

# Kaydet
OUTPUT = "data/raw_urls.csv"
df_all.to_csv(OUTPUT, index=False)

print("✅ Tüm veri seti birleştirildi")
print(f"📊 Toplam satır: {len(df_all)}")
print(df_all["label"].value_counts())
