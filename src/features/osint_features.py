import logging
import dns.resolver
from functools import lru_cache

# domain_utils.get_registered_domain is the single source of truth for domain parsing.
# This module intentionally does NOT define its own get_registered_domain to avoid
# the subdomain-vs-root-domain inconsistency that existed previously.
from src.features.domain_utils import get_registered_domain

logger = logging.getLogger(__name__)

# Re-export so API layer can import from one place
__all__ = ["extract_osint_features", "get_registered_domain"]


@lru_cache(maxsize=512)
def _cached_dns_lookup(domain: str) -> tuple:
    """
    Perform DNS lookups for a domain and return results as an immutable tuple
    so lru_cache can store them.  Cached for the lifetime of the process,
    which is fine for a prediction service (domains rarely change mid-session).

    Returns: (dns_a_record_count, has_mx_record, mx_record_count,
               txt_record_count, has_spf_record)
    """
    dns_a_record_count = 0
    has_mx_record = 0
    mx_record_count = 0
    txt_record_count = 0
    has_spf_record = 0

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        # A record
        try:
            answers = resolver.resolve(domain, "A")
            dns_a_record_count = len(answers)
        except Exception as e:
            logger.debug("[OSINT] A-record lookup failed for %s: %s(%s)", domain, type(e).__name__, e)

        # MX record
        try:
            answers = resolver.resolve(domain, "MX")
            mx_record_count = len(answers)
            has_mx_record = 1 if mx_record_count > 0 else 0
        except Exception as e:
            logger.debug("[OSINT] MX-record lookup failed for %s: %s(%s)", domain, type(e).__name__, e)

        # TXT / SPF
        try:
            answers = resolver.resolve(domain, "TXT")
            txt_record_count = len(answers)
            for record in answers:
                if "v=spf1" in str(record).lower():
                    has_spf_record = 1
                    break
        except Exception as e:
            logger.debug("[OSINT] TXT-record lookup failed for %s: %s(%s)", domain, type(e).__name__, e)

    except Exception as e:
        logger.warning("[OSINT] Unexpected error during DNS lookup for %s: %s(%s)", domain, type(e).__name__, e)

    return (dns_a_record_count, has_mx_record, mx_record_count, txt_record_count, has_spf_record)


def extract_osint_features(domain: str) -> dict:
    """Extract live DNS-based OSINT features for a domain or URL.

    Uses domain_utils.get_registered_domain (root-domain only, no subdomain)
    to ensure consistency with the whitelist and feature pipeline.
    Results are cached per process via lru_cache on _cached_dns_lookup.
    """
    features = {
        "has_mx_record": 0,
        "has_spf_record": 0,
        "dns_a_record_count": 0,
        "txt_record_count": 0,
        "mx_record_count": 0,
    }

    clean_domain = get_registered_domain(str(domain).strip())
    if not clean_domain:
        logger.debug("[OSINT] Could not parse domain from: %s", domain)
        return features

    (
        features["dns_a_record_count"],
        features["has_mx_record"],
        features["mx_record_count"],
        features["txt_record_count"],
        features["has_spf_record"],
    ) = _cached_dns_lookup(clean_domain)

    return features