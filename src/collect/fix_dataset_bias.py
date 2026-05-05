import pandas as pd
import random
import os

def fix_dataset_bias(input_csv="data/raw_urls.csv", output_csv="data/debiased_urls.csv"):
    print(f"'{input_csv}' dosyası okunuyor...")
    df = pd.read_csv(input_csv)

    # Güvenli (0) ve Zararlı (1) verileri ayır
    benign = df[df['label'] == 0].copy()
    malicious = df[df['label'] == 1].copy()
    
    print(f"Toplam Güvenli: {len(benign)}, Toplam Zararlı: {len(malicious)}")

    # Gerçek dünyada çok sık görülen, tamamen GÜVENLİ alt sayfa (path) örnekleri
    safe_paths = [
        "/", "/index.html", "/about-us", "/contact",
        "/search?q=hello", "/login", "/register",
        "/home", "/products", "/category/tech",
        "/en/dashboard", "/wp-content/uploads/image.jpg",
        "/blog/post-123", "/terms-of-service"
    ]

    def augment_benign(url):
        url = str(url).strip()
        
        # Eğer zaten http/https varsa dokunma, yoksa gerçekçi bir şekilde ekle
        if not url.startswith("http"):
            # %80 ihtimalle https, %20 ihtimalle http
            scheme = "https://" if random.random() < 0.8 else "http://"
            # %50 ihtimalle www. ekle
            prefix = "www." if random.random() < 0.5 else ""
            url = f"{scheme}{prefix}{url}"

        # Güvenli URL'lerin %75'ine alt sayfa (path) ekle ki model '/' işaretini sadece zararlılarda sanmasın!
        if random.random() < 0.75:
            url = url + random.choice(safe_paths)

        return url

    print("\nAdalet sağlanıyor... Güvenli (0) etiketli veriler gerçek dünya formatına dönüştürülüyor...")
    benign['url'] = benign['url'].apply(augment_benign)

    print("Veriler birleştiriliyor ve karıştırılıyor...")
    # Verileri tekrar birleştir ve satırları rastgele karıştır (shuffle)
    fixed_df = pd.concat([benign, malicious]).sample(frac=1, random_state=42).reset_index(drop=True)

    # Yeni, hilesiz veriyi kaydet
    fixed_df.to_csv(output_csv, index=False)
    print(f"\n✅ Mükemmel! Kopya çekmeyi engelleyen yeni veri seti şuraya kaydedildi: {output_csv}")

if __name__ == "__main__":
    # Eğer data klasörü yoksa hata vermemesi için
    os.makedirs("data", exist_ok=True)
    fix_dataset_bias()