import pandas as pd
from urllib.parse import urlparse
import tldextract
import os

print("TLDExtract hazırlanıyor...")
_extractor = tldextract.TLDExtract(suffix_list_urls=None)

def extract_base_domain(url: str) -> str:
    """URL'nin sonundaki her şeyi (path, query) atar. Sadece temiz domaini bırakır."""
    if not isinstance(url, str) or not url.strip():
        return ""
        
    try:
        url = url.strip().lower()
        has_scheme = url.startswith('http://') or url.startswith('https://')
        temp_url = url if has_scheme else 'http://' + url
        
        ext = _extractor(temp_url)
        
        # www temizliği
        subdomain = ext.subdomain
        if subdomain.startswith('www.'):
            subdomain = subdomain[4:]
        elif subdomain == 'www':
            subdomain = ''
            
        root_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        
        # SADECE DOMAIN KALIYOR (Path yok, HTTP yok, Slash yok!)
        clean_domain = f"{subdomain + '.' if subdomain else ''}{root_domain}"
        
        return clean_domain
    except Exception:
        return ""

def create_domain_only_dataset(input_csv="data/raw_urls.csv", output_csv="data/domain_only_urls.csv"):
    print(f"'{input_csv}' okunuyor...")
    df = pd.read_csv(input_csv)
    
    # URL'leri sadece domain kalacak şekilde kırp
    print("Tüm URL'ler acımasızca kesiliyor (Sadece Domain bırakılıyor)...")
    df['domain'] = df['url'].apply(extract_base_domain)
    
    # Hatalı/Boş olanları sil
    df = df[df['domain'] != ""]
    
    # KRİTİK NOKTA: Path'leri silince aynı domainden binlerce kopya kalabilir.
    # Örn: paypal.com/a, paypal.com/b -> ikisi de paypal.com oldu.
    # Bu kopyaları (duplicate) siliyoruz!
    print("Kopya (Duplicate) domainler temizleniyor...")
    
    # Eğer aynı domain hem 0 hem 1 etiketine sahipse (örn: hacklenmiş site), 
    # güvenlik gereği onu Zararlı (1) olarak kabul et.
    df = df.sort_values('label', ascending=False).drop_duplicates(subset=['domain'], keep='first')
    
    # İhtiyacımız olan sütunları alalım ve ismini düzeltelim
    df = df[['domain', 'label']].rename(columns={'domain': 'url'})
    
    # VERİYİ RASTGELE KARIŞTIRMA (SHUFFLING) İŞLEMİ
    print("Veri seti rastgele karıştırılıyor...")
    # frac=1 tüm veriyi alıp karıştırır. random_state her çalıştırmada aynı rastgeleliği verir (opsiyonel).
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Son CSV'yi kaydet
    df.to_csv(output_csv, index=False)
    
    print(f"\n✅ İşlem Tamamlandı! Yepyeni ve RASTGELE karıştırılmış Domain veri seti: {output_csv}")
    print(f"Benzersiz (Unique) Domain Sayısı: {len(df)}")

if __name__ == "__main__":
    create_domain_only_dataset()