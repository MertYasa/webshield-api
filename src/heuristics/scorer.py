# src/heuristics/scorer.py
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import urlparse, unquote

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HEXISH_RE = re.compile(r"^[0-9a-fA-F]+$")
SUSPICIOUS_EXT_RE = re.compile(r"\.(?:exe|scr|js|jse|vbs|vbe|ps1|bat|cmd|dll|lnk|jar|msi|iso|img)(?:$|\?)", re.IGNORECASE)

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "account", "update",
    "password", "confirm", "unlock", "billing", "payment", "invoice", "wallet",
    "oauth", "sso", "auth", "support", "recover", "reset"
]

SHORTENER_HOSTS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly", "ow.ly", "buff.ly"
}

HIGH_RISK_TLDS = {
    "ru", "cn", "tk", "ml", "ga", "gq", "cf", "top", "xyz", "click", "zip", "mov"
}

COMMON_SAFE_TLDS = {"com", "org", "net", "edu", "gov", "mil"}

@dataclass
class HeuristicResult:
    score: float
    reasons: List[str]
    details: Dict[str, float]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _get_host_parts(url: str) -> Tuple[str, str, str]:
    # Chrome her zaman protokol yollar, fail-safe olarak HTTPS ekliyoruz (HTTP cezası yememek için)
    p = urlparse(url if "://" in url else "https://" + url)
    host = (p.hostname or "").lower().strip(".")
    if not host:
        return "", "", ""

    parts = host.split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        reg = ".".join(parts[-2:])
    else:
        tld = parts[0]
        reg = parts[0]
    return host, reg, tld


def score_url(url: str) -> HeuristicResult:
    u = (url or "").strip()
    # Varsayılan fallback HTTPS yapıldı
    p = urlparse(u if "://" in u else "https://" + u)

    host, reg_domain, tld = _get_host_parts(u)
    path = unquote(p.path or "")
    query = unquote(p.query or "")
    full_path = (path + ("?" + query if query else "")).lower()

    reasons: List[str] = []
    contrib: Dict[str, float] = {}

    risk = 0.0

    # R1: http scheme (Cezası hafifletildi)
    if (p.scheme or "").lower() == "http":
        add = 0.10
        if any(k in full_path for k in ["login", "verify", "password", "account", "signin"]):
            add = 0.25
            reasons.append("http_scheme_with_auth_path")
        else:
            reasons.append("http_scheme")
        risk += add
        contrib["http_scheme"] = add

    # R2: IP host
    if host and IPV4_RE.match(host):
        add = 0.35
        reasons.append("ip_in_host")
        risk += add
        contrib["ip_in_host"] = add

    # R3: explicit port
    if p.port is not None:
        add = 0.12
        reasons.append("explicit_port")
        risk += add
        contrib["explicit_port"] = add

    # R4: @ in URL
    if "@" in u:
        add = 0.35
        reasons.append("at_symbol_in_url")
        risk += add
        contrib["at_symbol_in_url"] = add

    # R5: suspicious file extensions
    if SUSPICIOUS_EXT_RE.search(u):
        add = 0.35
        reasons.append("suspicious_file_extension")
        risk += add
        contrib["suspicious_file_extension"] = add

    # R6: many subdomains (www ve mail istisnaları eklendi)
    if host:
        clean_host = host.replace("www.", "").replace("mail.", "")
        subdomain_count = max(0, len(clean_host.split(".")) - 2)
        if subdomain_count >= 3:
            add = 0.05 + min(0.10, 0.02 * (subdomain_count - 3))
            reasons.append("many_subdomains")
            risk += add
            contrib["many_subdomains"] = add

    # R7: suspicious keywords
    kw_hits = [k for k in SUSPICIOUS_KEYWORDS if k in full_path]
    if len(kw_hits) >= 2:
        add = 0.18
        reasons.append("multiple_suspicious_keywords")
        risk += add
        contrib["multiple_suspicious_keywords"] = add
    elif len(kw_hits) == 1:
        add = 0.08
        reasons.append("suspicious_keyword")
        risk += add
        contrib["suspicious_keyword"] = add

    # R8: url shortener
    if reg_domain in SHORTENER_HOSTS or host in SHORTENER_HOSTS:
        add = 0.25
        reasons.append("url_shortener")
        risk += add
        contrib["url_shortener"] = add

    # R9: high-risk tld
    if tld in HIGH_RISK_TLDS:
        add = 0.10
        reasons.append(f"high_risk_tld:{tld}")
        risk += add
        contrib["high_risk_tld"] = add

    # R10: long URL / long query
    if len(u) >= 120:
        add = 0.08
        reasons.append("very_long_url")
        risk += add
        contrib["very_long_url"] = add
    if len(query) >= 80:
        add = 0.08
        reasons.append("long_query")
        risk += add
        contrib["long_query"] = add

    # R11: high entropy tokens
    tokens = re.split(r"[^a-zA-Z0-9]+", (host + "/" + path).strip("/"))
    long_tokens = [t for t in tokens if len(t) >= 12]
    ent_hits = 0
    for t in long_tokens[:8]:
        ent = _shannon_entropy(t)
        if ent >= 3.3:
            ent_hits += 1
    if ent_hits >= 2:
        add = 0.10
        reasons.append("high_entropy")
        risk += add
        contrib["high_entropy"] = add

    # R12: hex-ish token
    hex_hits = 0
    for t in long_tokens[:8]:
        if len(t) >= 16 and HEXISH_RE.match(t):
            hex_hits += 1
    if hex_hits >= 1:
        add = 0.10
        reasons.append("hex_like_token")
        risk += add
        contrib["hex_like_token"] = add

    trust = 0.0

    # T1: https scheme
    if (p.scheme or "").lower() == "https":
        sub = 0.06
        trust += sub
        contrib["https_bonus"] = -sub

    # T2: no port, no IP
    if p.port is None and host and not IPV4_RE.match(host):
        sub = 0.04
        trust += sub
        contrib["no_port_no_ip_bonus"] = -sub

    # T3: safe tld & institutional domains
    host_parts = host.split(".")
    if len(host_parts) > 1 and any(p in {"edu", "gov", "mil", "bel", "k12", "int", "ac"} for p in host_parts[1:]):
        sub = 0.15  # Ekstra güven (+ puan)
        trust += sub
        contrib["institutional_domain_bonus"] = -sub
    elif tld in COMMON_SAFE_TLDS:
        sub = 0.03
        trust += sub
        contrib["common_tld_bonus"] = -sub

    # T4: clean path
    if len(path) <= 25 and not kw_hits and not SUSPICIOUS_EXT_RE.search(u):
        sub = 0.05
        trust += sub
        contrib["clean_path_bonus"] = -sub

    risk = max(0.0, risk - trust)
    score = max(0.0, min(1.0, risk))

    return HeuristicResult(score=score, reasons=reasons, details=contrib)