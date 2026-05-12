# WebShield — AI-Powered Phishing Detection

WebShield is a two-part security tool:

1. **Chrome Extension** — analyses every tab URL in real-time and shows a risk badge + popup.
2. **ML API** — FastAPI backend that runs URL through a machine-learning model, OSINT/DNS features, and a heuristic engine.

---

## Project Structure

```
webshield_ml/
├── data/
│   ├── webshield_ready_for_model.csv   # Training dataset
│   └── whitelist.csv                   # Trusted domains (one per line)
├── models/
│   └── webshield_ultimate_model.pkl    # Trained XGBoost bundle
├── src/
│   ├── api/
│   │   ├── app.py                      # FastAPI application
│   │   └── validators.py               # URL validation helpers
│   ├── features/
│   │   ├── domain_utils.py             # Root-domain extraction (single source of truth)
│   │   ├── osint_features.py           # DNS/OSINT feature extraction (with LRU cache)
│   │   └── url_features.py             # Lexical URL features for ML
│   ├── heuristics/
│   │   └── scorer.py                   # Rule-based heuristic engine
│   └── predict/
│       └── predict.py                  # Prediction pipeline (whitelist → ML → heuristics)
└── requirements.txt

webshield-extension/
├── manifest.json
├── background.js                       # Service worker (analysis, caching, badge)
├── popup.html / popup.js               # Extension popup UI
├── warning.html / warning.js           # Full-page phishing warning (XSS-safe)
├── icon.png
└── _locales/
    ├── en/messages.json
    └── tr/messages.json
```

---

## API — Quick Start

### 1. Create and activate virtual environment

```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# macOS / Linux
python -m venv venv
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> **Windows Unicode Note**  
> If you see `UnicodeEncodeError` on startup, set the console encoding before running:
> ```powershell
> $env:PYTHONIOENCODING = "utf-8"
> ```
> The API itself has been updated to use `logging` instead of emoji-heavy `print` statements, so this should no longer be required as of v1.3.0.

### 3. Run the API

```bash
# From the project root (webshield_ml/)
uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

### 4. Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOWED_ORIGINS` | `*` | Comma-separated CORS origins. Set to your extension origin in production. |

---

## API Endpoints

### `POST /predict`

Analyse a URL.

**Request**
```json
{ "url": "http://paypa1-secure.tk/login/verify" }
```

**Response**
```json
{
  "url": "http://paypa1-secure.tk/login/verify",
  "decision": "PHISHING",
  "confidence": "HIGH",
  "final_risk": 0.9312,
  "ml_score": 0.9654,
  "heuristic_score": 0.43,
  "osint_data": {
    "has_mx_record": 0,
    "has_spf_record": 0,
    "dns_a_record_count": 0,
    "txt_record_count": 0,
    "mx_record_count": 0
  },
  "reasons": ["http_scheme_with_auth_path", "suspicious_keyword", "high_risk_tld:tk"],
  "model_version": "webshield_ultimate_v2",
  "heuristic_version": "heuristic_engine_v1",
  "api_version": "1.3.0",
  "timestamp": "2026-05-12T20:00:00+00:00"
}
```

**Decision levels**

| Decision | final_risk range | Badge |
|----------|-----------------|-------|
| SAFE | < 0.30 | ✓✓ green |
| LOW RISK | 0.30 – 0.44 | ✓? lime |
| SUSPICIOUS | 0.45 – 0.59 | ?? amber |
| HIGH RISK | 0.60 – 0.74 | ?! orange |
| PHISHING | ≥ 0.75 | !! red |

---

### `POST /report-false-positive`

Report a URL that was incorrectly flagged.

```json
{ "url": "https://example.com" }
```

Reports are written to `data/false_positives.csv` with a timestamp for later review / retraining.

---

### `GET /health`

```json
{
  "status": "ok",
  "model_loaded": true,
  "whitelist_size": 842,
  "uptime_seconds": 3600,
  "api_version": "1.3.0"
}
```

### `GET /model-info`

Returns model version, threshold values, and feature group names.

---

## Chrome Extension — Installation

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `webshield-extension/` folder
5. The extension icon will appear in the toolbar

> The extension expects the API to be running at `https://webshield-api.online`.  
> For local development, change `API_URL` in `background.js` to `http://localhost:8000/predict`.

---

## Whitelist

Add one trusted root domain per line in `data/whitelist.csv`:

```
google.com
github.com
microsoft.com
```

Domains on the whitelist bypass ML analysis entirely and are immediately returned as `SAFE`.  
Cloud hosting domains (`github.io`, `vercel.app`, etc.) are excluded from the whitelist even if listed.

---

## Known Limitations / Future Work

- **Test suite**: No automated tests yet. Minimum viable `pytest` suite planned.
- **DNS cache TTL**: `lru_cache` caches per-process. A Redis-backed TTL cache would be better for production.
- **Icon sizes**: `icon.png` is a single 1024×1024 file. Separate 16/32/48/128 px versions would improve browser rendering.
- **evaluate_thresholds.py / build_osint_dataset.py**: These scripts target an older model format and will fail with the current model. Do not run them without updating to the current schema.
- **Data versioning**: Consider DVC or Git LFS for `data/` and `models/`.
