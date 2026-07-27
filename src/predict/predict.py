# src/predict/predict.py
import logging
import os

import joblib
import numpy as np
import pandas as pd
import tldextract
from urllib.parse import urlparse

from src.features.url_features import extract_url_features
from src.features.osint_features import extract_osint_features
from src.features.domain_utils import get_registered_domain
from src.heuristics.scorer import score_url

logger = logging.getLogger(__name__)

# ==================================================
# CONFIG — single source of truth for thresholds
# ==================================================
MODEL_PATH = "models/webshield_ultimate_model.pkl"
ML_WEIGHT = 0.85
HEURISTIC_WEIGHT = 0.15

# Decision thresholds — used by BOTH _decision_and_confidence and callers
SAFE_TH = 0.30
LOW_RISK_TH = 0.45
SUSPICIOUS_TH = 0.60
HIGH_RISK_TH = 0.75
# Above HIGH_RISK_TH → PHISHING

# Confidence boundary within each band
HIGH_CONF_SAFE_TH = 0.15     # final_risk < this → HIGH confidence SAFE
HIGH_CONF_PHISH_TH = 0.85    # final_risk > this → HIGH confidence PHISHING

# ==================================================
# WHITELIST
# ==================================================
GLOBAL_WHITELIST: set = set()

# Cloud hosting domains that should NOT bypass ML even if they appear in whitelist
CLOUD_HOSTING_BLACKLIST = {
    "github.io", "vercel.app", "firebaseapp.com", "herokuapp.com",
    "netlify.app", "s3.amazonaws.com", "wixsite.com", "wordpress.com",
    "blogspot.com", "weebly.com", "repl.it", "glitch.me", "pages.dev",
}


def load_whitelist(file_path: str = "data/whitelist.csv") -> None:
    """Load trusted domains from CSV into GLOBAL_WHITELIST."""
    global GLOBAL_WHITELIST
    if not os.path.exists(file_path):
        logger.warning("[Whitelist] File not found at %s. Running without whitelist.", file_path)
        return

    count = 0
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if domain and domain != "domain" and domain not in CLOUD_HOSTING_BLACKLIST:
                GLOBAL_WHITELIST.add(domain)
                count += 1

    logger.info("[Whitelist] Loaded %d trusted domains (ML bypass enabled).", count)


load_whitelist()

# ==================================================
# MODEL LOADING
# ==================================================
_bundle = joblib.load(MODEL_PATH)
_model = _bundle["model"]
_extractor = tldextract.TLDExtract(suffix_list_urls=None)
logger.info("[Model] Loaded from %s", MODEL_PATH)


# ==================================================
# DECISION LOGIC — uses the threshold constants above
# ==================================================
def _decision_and_confidence(final_risk: float) -> tuple[str, str]:
    """
    Convert a final_risk float [0, 1] to a (decision, confidence) tuple.
    All boundaries are driven by the module-level threshold constants so
    there is a single source of truth.
    """
    if final_risk < SAFE_TH:
        confidence = "HIGH" if final_risk < HIGH_CONF_SAFE_TH else "MEDIUM"
        return "SAFE", confidence
    elif final_risk < LOW_RISK_TH:
        return "LOW RISK", "MEDIUM"
    elif final_risk < SUSPICIOUS_TH:
        return "SUSPICIOUS", "LOW"
    elif final_risk < HIGH_RISK_TH:
        return "HIGH RISK", "MEDIUM"
    else:
        confidence = "HIGH" if final_risk > HIGH_CONF_PHISH_TH else "MEDIUM"
        return "PHISHING", confidence


# ==================================================
# MAIN PREDICT FUNCTION
# ==================================================
def predict_url(url: str) -> dict:
    """Analyse a URL and return a structured risk assessment dict."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")

    raw_url = url.strip()
    root_domain = get_registered_domain(raw_url) or raw_url

    # --- 0. WHITELIST FAST-PASS ---
    if root_domain in GLOBAL_WHITELIST:
        logger.debug("[Predict] %s matched whitelist → SAFE (fast-pass)", root_domain)
        return {
            "url": raw_url,
            "ml_score": 0.0,
            "heuristic_score": 0.0,
            "final_risk": 0.0,
            "decision": "SAFE",
            "confidence": "HIGH",
            "osint_data": {
                "has_mx_record": 1, "has_spf_record": 1,
                "dns_a_record_count": 1, "txt_record_count": 1, "mx_record_count": 1,
            },
            "reasons": ["global_whitelist_trusted"],
        }

    # --- 1. OSINT (single fetch, cached internally) ---
    osint_feats = extract_osint_features(raw_url)
    osint_cols = ["has_mx_record", "has_spf_record", "dns_a_record_count", "txt_record_count", "mx_record_count"]
    X_osint = pd.DataFrame([osint_feats], columns=osint_cols).astype(float)

    # --- 2. DUAL-PASS ML ---
    # Pass A: full URL
    lex_feats_full = extract_url_features(raw_url)
    X_lex_full = pd.DataFrame([lex_feats_full]).astype(float)
    X_all_full = np.concatenate([X_lex_full.values, X_osint.values], axis=1)
    ml_score_full = float(_model.predict_proba(X_all_full)[0, 1])

    # Determine if URL has subdomain / non-trivial path
    p = urlparse(raw_url if "://" in raw_url else "https://" + raw_url)
    clean_host = (p.hostname or "").lower()

    if clean_host != root_domain or p.path not in ("", "/"):
        # Pass B: root domain only
        lex_feats_root = extract_url_features(root_domain)
        X_lex_root = pd.DataFrame([lex_feats_root]).astype(float)
        X_all_root = np.concatenate([X_lex_root.values, X_osint.values], axis=1)
        ml_score_root = float(_model.predict_proba(X_all_root)[0, 1])

        # 70% root domain weight + 30% full URL weight
        final_ml_score = (ml_score_root * 0.70) + (ml_score_full * 0.30)
        reasons = ["dual_pass_ml_active"]
        logger.debug("[Predict] Dual-pass: root=%.4f full=%.4f combined=%.4f", ml_score_root, ml_score_full, final_ml_score)
    else:
        final_ml_score = ml_score_full
        reasons = []
        logger.debug("[Predict] Single-pass: ml_score=%.4f", final_ml_score)

    # --- 3. HEURISTICS ---
    h = score_url(raw_url)
    heuristic_score = h.score
    reasons.extend(h.reasons)

    # --- 4. FINAL DECISION ---
    final_risk = min(1.0, (ML_WEIGHT * final_ml_score) + (HEURISTIC_WEIGHT * heuristic_score))
    decision, confidence = _decision_and_confidence(final_risk)

    logger.info(
        "[Predict] %s → %s (risk=%.4f ml=%.4f heuristic=%.4f)",
        root_domain, decision, final_risk, final_ml_score, heuristic_score,
    )

    return {
        "url": raw_url,
        "ml_score": round(final_ml_score, 4),
        "heuristic_score": round(heuristic_score, 4),
        "final_risk": round(final_risk, 4),
        "decision": decision,
        "confidence": confidence,
        "osint_data": osint_feats,
        "reasons": reasons,
    }