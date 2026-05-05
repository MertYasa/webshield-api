import pandas as pd
import os

def prepare_final_data():
    input_file = "data/webshield_ultimate_dataset.csv"
    output_file = "data/webshield_ready_for_model.csv"
    
    if not os.path.exists(input_file):
        print(f"⚠️ HATA: {input_file} bulunamadı!")
        return

    print("📦 Veri seti okunuyor...")
    df = pd.read_csv(input_file)
    
    # Sadece DMARC Sütununu Çöpe At
    if 'has_dmarc_record' in df.columns:
        df = df.drop(columns=['has_dmarc_record'])
        print("🗑️ 'has_dmarc_record' (Hepsi 0 olduğu için) veri setinden atıldı.")

    # SAYILARA DOKUNMUYORUZ (Scaling iptal!)
    print("⚖️ Sayılar orijinal (anlaşılır) tam sayı haliyle bırakıldı.")

    # Kaydet
    df.to_csv(output_file, index=False)
    print(f"\n🎉 KUSURSUZ! XGBoost için nihai veri hazır: {output_file}")

if __name__ == "__main__":
    prepare_final_data()