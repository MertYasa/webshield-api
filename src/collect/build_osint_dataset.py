import pandas as pd
from tqdm import tqdm
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.features.osint_features import extract_osint_features

def process_single_row(row_data):
    index, row = row_data
    domain = str(row['url']).strip()
    label = row['label']
    
    features = extract_osint_features(domain)
    
    return {
        "url": domain,
        "label": label,
        "has_mx_record": features["has_mx_record"],
        "has_spf_record": features["has_spf_record"],
        "dns_a_record_count": features["dns_a_record_count"],
        "ssl_issuer": features["ssl_issuer"],
        "ssl_lifespan_days": features["ssl_lifespan_days"],
        "ssl_age_days": features["ssl_age_days"]
    }

def enrich_dataset_with_osint_multithread(input_csv="data/domain_only_urls.csv", output_csv="data/osint_enriched_urls.csv"):
    temp_csv = "data/osint_backup_temp.csv"
    print(f"📦 Ana veri seti {input_csv} okunuyor...")
    df = pd.read_csv(input_csv)
    total_rows = len(df)
    
    osint_results = []
    processed_urls = set()

    # --- AKILLI DEVAM ETME (RESUME) MANTIĞI ---
    if os.path.exists(temp_csv):
        print("🔄 Önceki tarama yedeği bulundu! Kaldığı yerden devam edilecek...")
        backup_df = pd.read_csv(temp_csv)
        osint_results = backup_df.to_dict('records')
        processed_urls = set(backup_df['url'].astype(str).str.strip())
        print(f"✅ {len(processed_urls)} adet site zaten taranmış. Atlanıyor...")

    # Henüz taranmamış (kalan) siteleri filtrele
    df_remaining = df[~df['url'].astype(str).str.strip().isin(processed_urls)]
    remaining_rows = len(df_remaining)
    
    if remaining_rows == 0:
        print("✨ Taranacak yeni site kalmadı! İşlem zaten tamamlanmış.")
        pd.DataFrame(osint_results).to_csv(output_csv, index=False)
        return

    print(f"🚀 B PLANI AKTİF! Kalan {remaining_rows} site jet hızıyla taranıyor...")
    
    backup_interval = 2000 
    max_workers = 50 
    rows_to_process = list(df_remaining.iterrows())
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_row, row): row for row in rows_to_process}
        
        # DİKKAT: dynamic_ncols=True ekledik. Artık terminalde alt alta merdiven yapmayacak!
        for i, future in enumerate(tqdm(as_completed(futures), total=remaining_rows, desc="OSINT Taramasi", dynamic_ncols=True)):
            result = future.result()
            osint_results.append(result)
            
            # Her 2000 satırda bir ÜZERİNE YAZARAK yedeği güncelle
            if (i + 1) % backup_interval == 0:
                pd.DataFrame(osint_results).to_csv(temp_csv, index=False)

    print("\n✅ Tüm veri tarandı! Ana dosya kaydediliyor...")
    pd.DataFrame(osint_results).to_csv(output_csv, index=False)
    
    if os.path.exists(temp_csv):
        os.remove(temp_csv)
        
    print(f"🎉 BAŞARILI! Veri seti oluşturuldu: {output_csv}")

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    enrich_dataset_with_osint_multithread("data/domain_only_urls.csv", "data/osint_enriched_urls.csv")