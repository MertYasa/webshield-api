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

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from src.predict.predict import predict_url, GLOBAL_WHITELIST, SAFE_TH, HIGH_RISK_TH
from src.features.osint_features import extract_osint_features, get_registered_domain
from src.api.validators import validate_url, sanitize_url_for_logging, URLValidationError

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
# Example: ALLOWED_ORIGINS=chrome-extension://<id>
_raw_origins = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]
# Remove wildcard if present, unless explicitly needed for dev.
if "*" in ALLOWED_ORIGINS and os.getenv("ENVIRONMENT") != "development":
    logger.warning("Wildcard CORS detected. This is unsafe for production. Please configure ALLOWED_ORIGINS.")
    ALLOWED_ORIGINS = [o for o in ALLOWED_ORIGINS if o != "*"]

_START_TIME = time.time()

# ==================================================
# RATE LIMITER INIT
# ==================================================
limiter = Limiter(key_func=get_remote_address)

# ==================================================
# FASTAPI INIT
# ==================================================
app = FastAPI(
    title="WebShield API",
    version=API_VERSION,
    description="Phishing & malicious URL detection powered by ML + OSINT + Heuristics.",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else ["https://webshield-api.online"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

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


class FeedbackRequest(BaseModel):
    url: str = Field(..., max_length=2048)
    page_title: str = Field("", max_length=2048)
    message: str = Field(..., max_length=500)
    feedback_type: str = Field(..., max_length=100)
    timestamp: str
    extension_version: str


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
@limiter.limit("60/minute")
def predict_endpoint(req: PredictRequest, request: Request):
    """
    Analyse a URL and return a structured risk assessment.

    - Internal / browser-scheme URLs (e.g. chrome://) are fast-passed as SAFE.
    - All other URLs go through ML + OSINT + Heuristic pipeline.
    """
    try:
        url_stripped = req.url.strip()
        url_lower = url_stripped.lower()
        safe_url_log = sanitize_url_for_logging(url_stripped)

        # Fast-pass: non-http(s) schemes (browser internal pages, etc.)
        if not url_lower.startswith(("http://", "https://")):
            logger.debug("[/predict] Non-http URL fast-passed as SAFE: %s", safe_url_log)
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
            logger.warning("[/predict] URL validation failed: %s | url=%s", ve, safe_url_log)
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
@limiter.limit("20/minute")
def report_false_positive(req: ReportRequest, request: Request):
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


@app.post("/feedback", tags=["Feedback"])
@limiter.limit("10/minute")
def submit_feedback(req: FeedbackRequest, request: Request):
    """
    Accept user feedback and save to data/feedbacks.csv.
    """
    try:
        # Light URL validation for feedback endpoints
        try:
            validated_url = validate_url(req.url.strip())
        except URLValidationError as ve:
            raise HTTPException(status_code=422, detail=str(ve))
            
        safe_url_log = sanitize_url_for_logging(validated_url)

        os.makedirs("data", exist_ok=True)
        file_path = "data/feedbacks.csv"
        file_exists = os.path.isfile(file_path)

        fieldnames = [
            "timestamp", "url", "page_title", "feedback_type", "message", "extension_version"
        ]

        new_row = {
            "timestamp": req.timestamp,
            "url": validated_url,
            "page_title": req.page_title,
            "feedback_type": req.feedback_type,
            "message": req.message,
            "extension_version": req.extension_version,
        }

        with open(file_path, mode="a", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(new_row)

        logger.info("[/feedback] Received feedback of type %s for url: %s", req.feedback_type, safe_url_log)
        return {"status": "success", "message": "Feedback recorded successfully."}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("[/feedback] Error: %s(%s)", type(e).__name__, e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to record feedback.")