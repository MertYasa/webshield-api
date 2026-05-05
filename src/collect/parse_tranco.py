import pandas as pd

INPUT_FILE = "data/top-1m.csv"
OUTPUT_FILE = "data/tranco_legit_urls.csv"

# Tranco CSV: rank, domain
df = pd.read_csv(INPUT_FILE, header=None)

# İlk 25.000 domain yeterli
df = df.head(25000)

out = pd.DataFrame()
out["url"] = "https://" + df[1].astype(str)
out["label"] = 0

out.to_csv(OUTPUT_FILE, index=False)

print(f"✅ Tranco legit URL listesi hazır: {len(out)} satır")
print(f"📁 Kaydedilen dosya: {OUTPUT_FILE}")
