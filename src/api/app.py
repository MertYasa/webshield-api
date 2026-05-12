"""
WebShield FastAPI Application
"""
import csv
import logging
import logging.config
import os
import time
from datetime import datetime, timezone
from typing import Dict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.predict.predict import predict_url, GLOBAL_WHITELIST, SAFE_TH, HIGH_RISK_TH
from src.features.osint_features import extract_osint_features, get_registered_domain
from src.api.validators import validate_url, URLValidationError

# ==================================================
# LOGGING SETUP — no emoji, Windows-safe
# ==================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ==================================================
# CONFIG
# ==================================================
API_VERSION = "1.3.0"
MODEL_VERSION = "webshield_ultimate_v2"
HEURISTIC_VERSION = "heuristic_engine_v1"

# CORS: restrict in production via environment variable.
# Example: ALLOWED_ORIGINS=https://my-extension-host.com
_raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

_START_TIME = time.time()

# ==================================================
# FASTAPI INIT
# ==================================================
app = FastAPI(
    title="WebShield API",
    version=API_VERSION,
    description="Phishing & malicious URL detection powered by ML + OSINT + Heuristics.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================================================
# SCHEMAS
# ==================================================
class PredictRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="Full URL to analyse (http/https only).")


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
    url: str = Field(..., max_length=2048)


# ==================================================
# ENDPOINTS
# ==================================================

@app.get("/health", tags=["Meta"])
def health():
    """Liveness / readiness probe."""
    uptime_seconds = int(time.time() - _START_TIME)
    return {
        "status": "ok",
        "model_loaded": True,
        "whitelist_size": len(GLOBAL_WHITELIST),
        "uptime_seconds": uptime_seconds,
        "api_version": API_VERSION,
    }


@app.get("/model-info", tags=["Meta"])
def model_info():
    """Return model metadata and decision thresholds."""
    return {
        "model_version": MODEL_VERSION,
        "heuristic_version": HEURISTIC_VERSION,
        "api_version": API_VERSION,
        "thresholds": {
            "safe_below": SAFE_TH,
            "phishing_above": HIGH_RISK_TH,
        },
        "feature_groups": ["url_lexical (14)", "osint_dns (5)"],
    }


@app.post("/predict", response_model=PredictResponse, tags=["Predict"])
def predict_endpoint(req: PredictRequest):
    """
    Analyse a URL and return a structured risk assessment.

    - Internal / browser-scheme URLs (e.g. chrome://) are fast-passed as SAFE.
    - All other URLs go through ML + OSINT + Heuristic pipeline.
    """
    try:
        url_stripped = req.url.strip()
        url_lower = url_stripped.lower()

        # Fast-pass: non-http(s) schemes (browser internal pages, etc.)
        if not url_lower.startswith(("http://", "https://")):
            logger.debug("[/predict] Non-http URL fast-passed as SAFE: %s", url_stripped[:80])
            return {
                "url": url_stripped,
                "decision": "SAFE",
                "confidence": "HIGH",
                "final_risk": 0.0,
                "ml_score": 0.0,
                "heuristic_score": 0.0,
                "osint_data": {
                    "has_mx_record": 0, "has_spf_record": 0,
                    "dns_a_record_count": 0, "txt_record_count": 0, "mx_record_count": 0,
                },
                "reasons": ["browser_internal_page"],
                "model_version": MODEL_VERSION,
                "heuristic_version": HEURISTIC_VERSION,
                "api_version": API_VERSION,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # Validate URL structure
        try:
            validated_url = validate_url(url_stripped)
        except URLValidationError as ve:
            logger.warning("[/predict] URL validation failed: %s | url=%s", ve, url_stripped[:80])
            raise HTTPException(status_code=422, detail=str(ve))

        result = predict_url(validated_url)
        return {
            **result,
            "model_version": MODEL_VERSION,
            "heuristic_version": HEURISTIC_VERSION,
            "api_version": API_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("[/predict] Unhandled error: %s(%s)", type(e).__name__, e, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during analysis.")


@app.post("/report-false-positive", tags=["Feedback"])
def report_false_positive(req: ReportRequest):
    """
    Accept a false-positive report from the extension.
    The URL is normalised to root domain, enriched with live OSINT data,
    and appended to data/false_positives.csv for later review.
    """
    try:
        # Validate
        try:
            validated_url = validate_url(req.url.strip())
        except URLValidationError as ve:
            raise HTTPException(status_code=422, detail=str(ve))

        clean_domain = get_registered_domain(validated_url) or validated_url
        logger.info("[/report-false-positive] Received report for: %s", clean_domain)

        osint_data = extract_osint_features(clean_domain)

        new_row = {
            "url": clean_domain,
            "reported_at": datetime.now(timezone.utc).isoformat(),
            "label": 0,  # user asserts site is safe
            "has_mx_record": osint_data["has_mx_record"],
            "has_spf_record": osint_data["has_spf_record"],
            "dns_a_record_count": osint_data["dns_a_record_count"],
            "txt_record_count": osint_data["txt_record_count"],
            "mx_record_count": osint_data["mx_record_count"],
        }

        os.makedirs("data", exist_ok=True)
        file_path = "data/false_positives.csv"
        file_exists = os.path.isfile(file_path)

        fieldnames = [
            "url", "reported_at", "label",
            "has_mx_record", "has_spf_record",
            "dns_a_record_count", "txt_record_count", "mx_record_count",
        ]

        with open(file_path, mode="a", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(new_row)

        logger.info("[/report-false-positive] Recorded: %s", clean_domain)
        return {"status": "success", "domain": clean_domain, "message": "Report recorded successfully."}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("[/report-false-positive] Error: %s(%s)", type(e).__name__, e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to record report.")