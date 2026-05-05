# src/predict/predict.py
import os
import joblib
import pandas as pd
import numpy as np

from src.features.url_features import extract_url_features
from src.features.osint_features import extract_osint_features
from src.features.domain_utils import get_registered_domain
from src.heuristics.scorer import score_url
import tldextract
from urllib.parse import urlparse

# CONFIG
MODEL_PATH = "models/webshield_ultimate_model.pkl" 
ML_WEIGHT = 0.85  
HEURISTIC_WEIGHT = 0.15 
SAFE_TH = 0.35  
PHISHING_TH = 0.60

# --- BEYAZ LİSTE (WHITELIST) YAPILANDIRMASI ---
GLOBAL_WHITELIST = set()

# Tehlikeli Bulut Servisleri 
CLOUD_HOSTING_BLACKLIST = {
    "github.io", "vercel.app", "firebaseapp.com", "herokuapp.com", 
    "netlify.app", "s3.amazonaws.com", "wixsite.com", "wordpress.com", 
    "blogspot.com", "weebly.com", "repl.it", "glitch.me", "pages.dev"
}

def load_whitelist():
    file_path = "data/whitelist.csv" 
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                domain = line.strip().lower()
                if domain and domain != "domain" and domain not in CLOUD_HOSTING_BLACKLIST:
                    GLOBAL_WHITELIST.add(domain)
        print(f"✅ Whitelist yüklendi: {len(GLOBAL_WHITELIST)} site ML taramasından muaf tutulacak.")
    else:
        print(f"⚠️ Uyarı: Whitelist dosyası bulunamadı ({file_path}). Sistem Whitelist olmadan çalışacak.")

load_whitelist()

# Model yükleniyor
_bundle = joblib.load(MODEL_PATH)
_model = _bundle["model"]
_extractor = tldextract.TLDExtract(suffix_list_urls=None)

def _decision_and_confidence(final_risk: float):
    if final_risk < SAFE_TH: return "SAFE", "HIGH" if final_risk < 0.25 else "MEDIUM"
    elif final_risk < PHISHING_TH: return "SUSPICIOUS", "LOW"
    else: return "PHISHING", "HIGH" if final_risk > 0.85 else "MEDIUM"

def predict_url(url: str) -> dict:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")

    raw_url = url.strip()
    # Kök domaini çıkartıyoruz
    root_domain = get_registered_domain(raw_url) or raw_url

    # --- 0. BEYAZ LİSTE (FAST-PASS) ---
    if root_domain in GLOBAL_WHITELIST:
        return {
            "url": raw_url,
            "ml_score": 0.0,
            "heuristic_score": 0.0,
            "final_risk": 0.0,
            "decision": "SAFE",
            "confidence": "HIGH",
            "osint_data": {
                "has_mx_record": 1, "has_spf_record": 1, 
                "dns_a_record_count": 1, "txt_record_count": 1, "mx_record_count": 1
            },
            "reasons": ["global_whitelist_trusted"]
        }

    # --- 1. OSINT (Performans için tek sefer çekiyoruz) ---
    osint_feats = extract_osint_features(raw_url)
    osint_cols = ["has_mx_record", "has_spf_record", "dns_a_record_count", "txt_record_count", "mx_record_count"]
    X_osint = pd.DataFrame([osint_feats], columns=osint_cols).astype(float)

    # --- 2. İKİLİ ML KONTROLÜ (DUAL-PASS ALGORITHM) ---
    # Adım A: URL'nin tamamını ML'e sok
    lex_feats_full = extract_url_features(raw_url)
    X_lex_full = pd.DataFrame([lex_feats_full]).astype(float)
    X_all_full = np.concatenate([X_lex_full.values, X_osint.values], axis=1)
    ml_score_full = float(_model.predict_proba(X_all_full)[0, 1])

    # Kök domain mi yoksa subdomain/path mi içeriyor kontrol et
    p = urlparse(raw_url if "://" in raw_url else "https://" + raw_url)
    clean_host = (p.hostname or "").lower()
    
    # Adım B: Eğer URL'de subdomain veya yönlendirme(path) varsa İkili Doğrulama yap!
    if clean_host != root_domain or p.path not in ("", "/"):
        # Sadece root domainin özelliklerini çıkarıp modele sokuyoruz
        lex_feats_root = extract_url_features(root_domain)
        X_lex_root = pd.DataFrame([lex_feats_root]).astype(float)
        X_all_root = np.concatenate([X_lex_root.values, X_osint.values], axis=1)
        ml_score_root = float(_model.predict_proba(X_all_root)[0, 1])
        
        # Algoritma: %60 Kök Domain Ağır Basar + %40 Tam URL Etki Eder
        final_ml_score = (ml_score_root * 0.60) + (ml_score_full * 0.40)
        reasons = ["dual_pass_ml_active"]
    else:
        # Zaten kök domain girilmiş, ikinci hesaba gerek yok
        final_ml_score = ml_score_full
        reasons = []

    # --- 3. HEURISTIC (Sağduyu Katmanı) ---
    h = score_url(raw_url)
    heuristic_score = h.score
    reasons.extend(h.reasons)

    # --- 4. KARAR MEKANİZMASI ---
    final_risk = min(1.0, (ML_WEIGHT * final_ml_score) + (HEURISTIC_WEIGHT * heuristic_score))
    decision, confidence = _decision_and_confidence(final_risk)

    return {
        "url": raw_url,
        "ml_score": round(final_ml_score, 4),
        "heuristic_score": round(heuristic_score, 4),
        "final_risk": round(final_risk, 4),
        "decision": decision,
        "confidence": confidence,
        "osint_data": osint_feats,
        "reasons": reasons
    }