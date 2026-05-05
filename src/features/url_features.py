# src/features/url_features.py
import re
from urllib.parse import urlparse, unquote
import tldextract

HIGH_RISK_TLDS = {'xyz', 'top', 'ru', 'biz', 'info', 'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'click'}

PHISHING_KEYWORDS = {
    "login", "signin", "secure", "verify", "account", "update", "bank",
    "password", "auth", "confirm", "support", "recover", "wallet", "invoice"
}

_extractor = tldextract.TLDExtract(suffix_list_urls=None)

def normalize_for_ml(url: str) -> str:
    try:
        url = unquote(url.strip().lower()).split(" ")[0]
        
        has_scheme = url.startswith('http://') or url.startswith('https://')
        temp_url = url if has_scheme else 'https://' + url
        
        parsed = urlparse(temp_url)
        ext = _extractor(temp_url)
        
        subdomain = ext.subdomain
        if subdomain.startswith('www.'):
            subdomain = subdomain[4:]
        elif subdomain == 'www':
            subdomain = ''
            
        root_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        path_parts = [p for p in parsed.path.split('/') if p]
        first_path = f"/{path_parts[0]}" if path_parts else ""
        
        clean_url = f"{subdomain + '.' if subdomain else ''}{root_domain}{first_path}"
        return clean_url
    except Exception:
        return url


def extract_url_features(url: str) -> dict:
    feats = {
        "url_length": 0,
        "domain_length": 0,
        "path_length": 0,
        "has_ip": 0,
        "count_at": 0,
        "count_dash": 0,
        "count_dot": 0,
        "count_slash": 0,
        "count_equals": 0,
        "digit_ratio": 0.0,
        "has_https": 0,
        "subdomain_count": 0,
        "is_suspicious_tld": 0,
        "has_embedded_domain": 0,
        "has_phishing_keyword": 0
    }

    if not isinstance(url, str) or not url.strip():
        return feats

    original_url = url.strip()
    feats["url_length"] = len(original_url)
    
    # Protokol yoksa varsayılan HTTPS yapıldı
    temp_url = original_url if "://" in original_url else "https://" + original_url
    parsed = urlparse(temp_url)
    ext = _extractor(temp_url)
    
    # 2. UZUNLUK VE KARAKTER SAYIMLARI
    feats["domain_length"] = len(parsed.netloc) # Sadece kök domaini değil host uzunluğunu alır
    feats["path_length"] = len(parsed.path)
    feats["count_at"] = original_url.count("@")
    feats["count_dash"] = original_url.count("-")
    
    # --- KRİTİK DEĞİŞİKLİK BURADA ---
    # Modelin URL'deki noktaları sayarak kolaya kaçmasını engelliyoruz (Kör ettik)
    feats["count_dot"] = 0 
    
    feats["count_slash"] = original_url.count("/")
    feats["count_equals"] = original_url.count("=")
    feats["digit_ratio"] = sum(c.isdigit() for c in original_url) / max(len(original_url), 1)

    # 3. PROTOKOL VE IP KONTROLÜ
    feats["has_https"] = 1 if parsed.scheme.lower() == "https" else 0
    # IP formatı sıkılaştırıldı
    feats["has_ip"] = 1 if re.search(r"^(\d{1,3}\.){3}\d{1,3}$", parsed.netloc) else 0

    # 4. SUBDOMAIN (ALT ALAN ADI) ANALİZİ
    clean_subdomain = ext.subdomain.replace('www.', '').replace('www', '')
    raw_sub_count = len([s for s in clean_subdomain.split(".") if s]) if clean_subdomain else 0
    
    # --- KRİTİK DEĞİŞİKLİK BURADA ---
    # Modelin subdomain sayısına saplantılı hale gelmemesi için 0'a sabitliyoruz.
    # Subdomain riskini zaten Sezgisel Motor (scorer.py) hesaplıyor!
    feats["subdomain_count"] = 0

    # 5. RİSKLİ UZANTI (TLD) KONTROLÜ
    if ext.suffix.lower() in HIGH_RISK_TLDS:
        feats["is_suspicious_tld"] = 1

    # 6. GİZLENMİŞ (EMBEDDED) DOMAIN KONTROLÜ
    embedded_pattern = r'[a-zA-Z0-9-]+\.(com|net|org|ru|info|xyz|biz)'
    if re.search(embedded_pattern, parsed.path):
        feats["has_embedded_domain"] = 1

    # 7. PHISHING ANAHTAR KELİME KONTROLÜ
    url_lower = original_url.lower()
    if any(keyword in url_lower for keyword in PHISHING_KEYWORDS):
        feats["has_phishing_keyword"] = 1

    return feats