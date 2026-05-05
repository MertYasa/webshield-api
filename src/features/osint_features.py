import dns.resolver
from urllib.parse import urlparse
import tldextract

_extractor = tldextract.TLDExtract(suffix_list_urls=None)

def get_registered_domain(url: str) -> str:
    try:
        temp_url = url if "://" in url else "http://" + url
        ext = _extractor(temp_url)
        full_domain = f"{ext.subdomain}.{ext.domain}.{ext.suffix}" if ext.subdomain else f"{ext.domain}.{ext.suffix}"
        return full_domain.strip(".")
    except:
        return ""

def extract_osint_features(domain: str) -> dict:
    """Canlı sistemde (Predict) saniyeler içinde sadece gerekli DNS verilerini çeker."""
    features = {
        "has_mx_record": 0,
        "has_spf_record": 0,
        "dns_a_record_count": 0,
        "txt_record_count": 0,
        "mx_record_count": 0
    }
    
    clean_domain = get_registered_domain(str(domain).strip())
    if not clean_domain:
        return features

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        # A Kaydı
        try:
            answers = resolver.resolve(clean_domain, 'A')
            features["dns_a_record_count"] = len(answers)
        except: pass

        # MX ve MX Sayısı
        try:
            answers = resolver.resolve(clean_domain, 'MX')
            features["has_mx_record"] = 1 if len(answers) > 0 else 0
            features["mx_record_count"] = len(answers)
        except: pass
            
        # TXT ve SPF
        try:
            answers = resolver.resolve(clean_domain, 'TXT')
            features["txt_record_count"] = len(answers)
            for record in answers:
                if "v=spf1" in str(record).lower():
                    features["has_spf_record"] = 1
                    break
        except: pass
            
    except Exception:
        pass

    return features