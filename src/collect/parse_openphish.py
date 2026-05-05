import pandas as pd

INPUT_FILE = "data/openphish.txt"
OUTPUT_FILE = "data/openphish_urls.csv"

urls = []

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    for line in f:
        url = line.strip()
        if url.startswith("http"):
            urls.append(url)

df = pd.DataFrame(urls, columns=["url"])
df["label"] = 1

df.to_csv(OUTPUT_FILE, index=False)

print(f"✅ OpenPhish URL listesi hazır: {len(df)} satır")
print(f"📁 Kaydedilen dosya: {OUTPUT_FILE}")
