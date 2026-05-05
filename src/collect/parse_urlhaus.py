import pandas as pd

INPUT_FILE = "data/urlhaus_recent.csv"
OUTPUT_FILE = "data/urlhaus_urls.csv"

# URLhaus CSV:
# - Başında # ile başlayan yorum satırları var
# - Ayraç virgül (,)
df = pd.read_csv(
    INPUT_FILE,
    comment="#",
    header=None
)

# Kolonları manuel isimlendiriyoruz
df.columns = [
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter"
]

# Sadece URL kolonunu al
urls = df[["url"]].copy()

# Boş olanları at
urls = urls.dropna()
urls = urls[urls["url"].str.len() > 0]

# WebShield için: malicious / phishing tarafı
urls["label"] = 1

urls.to_csv(OUTPUT_FILE, index=False)

print(f"✅ URLhaus URL listesi hazır: {len(urls)} satır")
print(f"📁 Kaydedilen dosya: {OUTPUT_FILE}")
