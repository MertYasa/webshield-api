import pandas as pd
import os

def clean_useless_columns():
    # Ana dizinden (root) çalıştırdığımız için yollar data/ şeklinde kalıyor
    input_file = "data/osint_enriched_urls.csv" # Tarama tamamen bittiyse bunu "data/osint_enriched_urls.csv" yapabilirsin
    output_file = "data/webshield_final_dataset.csv"

    if not os.path.exists(input_file):
        print(f"⚠️ HATA: {input_file} bulunamadı! Dosya adını veya yolunu kontrol et.")
        return

    print(f"📦 {input_file} okunuyor...")
    df = pd.read_csv(input_file)
    
    # İşe yaramayan (hep aynı değeri dönen) SSL sütunlarını belirliyoruz
    cols_to_drop = ['ssl_issuer', 'ssl_lifespan_days', 'ssl_age_days']
    
    # Sütunları veri setinden siliyoruz (eğer tabloda varsa)
    df_cleaned = df.drop(columns=[col for col in cols_to_drop if col in df.columns])
    
    # Yeni ve temiz dosyayı kaydet
    df_cleaned.to_csv(output_file, index=False)
    
    print("\n✅ Temizlik Operasyonu Başarılı!")
    print(f"🗑️ Çöpe atılan sütunlar: {cols_to_drop}")
    print(f"🎉 XGBoost modeli için tertemiz ve hazır veri seti oluşturuldu: {output_file}")

if __name__ == "__main__":
    clean_useless_columns()