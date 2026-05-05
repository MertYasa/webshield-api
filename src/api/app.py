import os  # <--- KRİTİK EKSİK BURADAYDI
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Dict

from src.predict.predict import predict_url
from src.features.osint_features import extract_osint_features, get_registered_domain

# ==================================================
# CONFIG (API-LEVEL)
# ==================================================
API_VERSION = "1.2.0"
MODEL_VERSION = "webshield_ultimate_v2"
HEURISTIC_VERSION = "heuristic_engine_v1"

# ==================================================
# FASTAPI INIT
# ==================================================
app = FastAPI(title="WebShield API", version=API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================================================
# SCHEMAS
# ==================================================
class PredictRequest(BaseModel):
    url: str

class PredictResponse(BaseModel):
    url: str
    decision: str
    confidence: str
    final_risk: float
    ml_score: float
    heuristic_score: float
    osint_data: Dict[str, float]
    reasons: list[str]
    model_version: str
    heuristic_version: str
    api_version: str
    timestamp: str

class ReportRequest(BaseModel):
    url: str

# ==================================================
# ENDPOINTS
# ==================================================

@app.post("/predict", response_model=PredictResponse)
def predict_endpoint(req: PredictRequest):
    try:
        url_lower = req.url.lower().strip()
        
        # 1. CHROME EKLENTİSİ FİLTRESİ (Fast-Pass)
        # Sadece http ve https olanları analiz et, tarayıcı sayfalarını es geç.
        if not url_lower.startswith(("http://", "https://")):
            return {
                "url": req.url,
                "decision": "SAFE",
                "confidence": "HIGH",
                "final_risk": 0.0,
                "ml_score": 0.0,
                "heuristic_score": 0.0,
                "osint_data": {"has_mx_record": 0, "has_spf_record": 0, "dns_a_record_count": 0, "txt_record_count": 0, "mx_record_count": 0},
                "reasons": ["browser_internal_page"],
                "model_version": MODEL_VERSION,
                "heuristic_version": HEURISTIC_VERSION,
                "api_version": API_VERSION,
                "timestamp": datetime.utcnow().isoformat()
            }

        # Normal analiz süreci...
        result = predict_url(req.url)
        return {
            **result,
            "model_version": MODEL_VERSION,
            "heuristic_version": HEURISTIC_VERSION,
            "api_version": API_VERSION,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        print(f"Server Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/report-false-positive")
def report_false_positive(req: ReportRequest):
    try:
        os.makedirs("data", exist_ok=True)
        file_path = "data/false_positives.csv"
        
        # 1. URL'yi veri setindeki formata (sadece domain) getiriyoruz
        clean_url = get_registered_domain(req.url)
        if not clean_url:
            clean_url = req.url # Fallback: Temizlenemezse orijinali kalsın
            
        print(f"🕵️ Bildirilen site normalize ediliyor: {clean_url}")
        
        # 2. Anlık OSINT verilerini çekelim
        osint_data = extract_osint_features(clean_url)
        
        # 3. Veri seti ile BİREBİR AYNI satır yapısı (timestamp kaldırıldı)
        new_row = {
            "url": clean_url,
            "label": 0, # Kullanıcı güvenli dediği için 0
            "has_mx_record": osint_data["has_mx_record"],
            "has_spf_record": osint_data["has_spf_record"],
            "dns_a_record_count": osint_data["dns_a_record_count"],
            "txt_record_count": osint_data["txt_record_count"],
            "mx_record_count": osint_data["mx_record_count"]
        }
        
        file_exists = os.path.isfile(file_path)
        
        # 4. CSV'ye Yazma
        import csv
        with open(file_path, mode='a', encoding='utf-8', newline='') as f:
            # Sütun sırasını ana veri setinle aynı yapıyoruz
            fieldnames = ["url", "label", "has_mx_record", "has_spf_record", 
                         "dns_a_record_count", "txt_record_count", "mx_record_count"]
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(new_row)
            
        print(f"✅ KUSURSUZ KAYIT: {clean_url} ana veri seti formatında kaydedildi.")
        return {"status": "success", "message": "Veri setiyle uyumlu kayıt yapıldı."}
    
    except Exception as e:
        print(f"Kayıt Hatası: {e}")
        raise HTTPException(status_code=500, detail="Uyumlu veri yazılamadı.")