import tldextract

_extractor = tldextract.TLDExtract(suffix_list_urls=None)

def get_registered_domain(url: str):
    try:
        if url is None:
            return None
        url = str(url).strip()
        if not url:
            return None

        ext = _extractor(url)

        if not ext.domain:
            return None

        if not ext.suffix:
            return ext.domain
            
        return f"{ext.domain}.{ext.suffix}"
    except Exception:
        return None