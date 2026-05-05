import pandas as pd
from tqdm import tqdm
import os
import dns.resolver
import tldextract
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 1. SÜPER DNS MOTORU ---
def get_registered_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

def extract_advanced_dns(domain: str) -> dict:
    """Sadece DMARC, TXT Sayısı ve MX Sayısını jet hızıyla çeker."""
    features = {
        "has_dmarc_record": 0,
        "txt_record_count": 0,
        "mx_record_count": 0
    }
    
    clean_domain = get_registered_domain(str(domain).strip())
    if not clean_domain:
        return features

    resolver = dns.resolver.Resolver()
    # SSL olmadığı için süreyi çok kısa tutabiliriz, DNS anında cevap verir
    resolver.timeout = 2
    resolver.lifetime = 2
    
    # 1. DMARC Kaydı (_dmarc. alt alan adına atılan özel TXT sorgusu)
    try:
        dmarc_domain = f"_dmarc.{clean_domain}"
        answers = resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            if "v=DMARC1" in str(rdata).upper():
                features["has_dmarc_record"] = 1
                break
    except Exception:
        pass
        
    # 2. TXT Kaydı Sayısı (Kurumsal sitelerin çöplüğü)
    try:
        answers = resolver.resolve(clean_domain, 'TXT')
        features["txt_record_count"] = len(answers)
    except Exception:
        pass
        
    # 3. MX Kaydı Sayısı (Altyapı büyüklüğü)
    try:
        answers = resolver.resolve(clean_domain, 'MX')
        features["mx_record_count"] = len(answers)
    except Exception:
        pass
        
    return features

# --- 2. MULTITHREAD İŞÇİ FONKSİYONU ---
def process_single_row(row_data):
    index, row = row_data
    domain = row['url']
    
    new_features = extract_advanced_dns(domain)
    
    # Eski satırdaki tüm verileri al, üstüne yeni özellikleri ekle
    row_dict = row.to_dict()
    row_dict.update(new_features)
    
    return row_dict

# --- 3. ANA YAMA (PATCH) OPERASYONU ---
def apply_dns_patch():
    input_file = "data/webshield_final_dataset.csv"
    output_file = "data/webshield_ultimate_dataset.csv"
    temp_file = "data/dns_patch_backup.csv"
    
    if not os.path.exists(input_file):
        print(f"⚠️ HATA: {input_file} bulunamadı!")
        return

    print(f"📦 Temizlenmiş ana veri seti okunuyor: {input_file}")
    df = pd.read_csv(input_file)
    
    results = []
    processed_urls = set()

    # Akıllı Devam Etme (Resume)
    if os.path.exists(temp_file):
        print("🔄 Önceki yama yedeği bulundu! Kaldığı yerden devam edilecek...")
        backup_df = pd.read_csv(temp_file)
        results = backup_df.to_dict('records')
        processed_urls = set(backup_df['url'].astype(str).str.strip())
        print(f"✅ {len(processed_urls)} adet site zaten yamalandı. Atlanıyor...")

    df_remaining = df[~df['url'].astype(str).str.strip().isin(processed_urls)]
    remaining_rows = len(df_remaining)
    
    if remaining_rows == 0:
        print("✨ Taranacak yeni site kalmadı! İşlem tamamlanmış.")
        pd.DataFrame(results).to_csv(output_file, index=False)
        return

    print(f"🚀 SÜPER DNS YAMASI BAŞLIYOR! Kalan: {remaining_rows} site...")
    
    backup_interval = 2000
    # SSL olmadığı için işçi sayısını 100'e kadar çıkarıp şov yapabiliriz!
    max_workers = 100 
    rows_to_process = list(df_remaining.iterrows())
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_row, row): row for row in rows_to_process}
        
        for i, future in enumerate(tqdm(as_completed(futures), total=remaining_rows, desc="Süper DNS Yaması", dynamic_ncols=True)):
            result = future.result()
            results.append(result)
            
            if (i + 1) % backup_interval == 0:
                pd.DataFrame(results).to_csv(temp_file, index=False)

    print("\n✅ Yama operasyonu tamamlandı! Dosya kaydediliyor...")
    pd.DataFrame(results).to_csv(output_file, index=False)
    
    if os.path.exists(temp_file):
        os.remove(temp_file)
        
    print(f"🎉 KUSURSUZ ZAFER! XGBoost'u uçuracak Ultimate Veri Seti hazır: {output_file}")

if __name__ == "__main__":
    apply_dns_patch()