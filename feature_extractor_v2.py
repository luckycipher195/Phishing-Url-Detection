
from urllib.parse import urlparse, parse_qsl
from collections import Counter
import ipaddress
import math
import re
import tldextract


POPULAR_TLDS = {
    "com", "org", "net", "edu", "gov",
    "in", "co", "uk", "io", "info"
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1",
    ".sh", ".vbs", ".js", ".jar", ".msi"
}

# Offline suffix-list extraction
extract_domain = tldextract.TLDExtract(suffix_list_urls=())


def extract_features(url):

    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty")

    parsed = urlparse(
        url if "://" in url else "http://" + url
    )

    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise ValueError("URL must contain a valid hostname")

    # Validate port number
    try:
        parsed.port
    except ValueError:
        raise ValueError("URL contains an invalid port number")

    # Reject whitespace in hostname
    if any(char.isspace() for char in hostname):
        raise ValueError("URL contains invalid whitespace in hostname")

    # Detect IP address
    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
        domain_parts = None
    except ValueError:
        has_ip = 0
        domain_parts = extract_domain(hostname)

    # Extract domain and suffix
    if has_ip:
        domain_name = hostname
        subdomain_count = 0
        tld = ""
    else:
        domain_name = domain_parts.domain
        tld = domain_parts.suffix
        subdomain_count = (
            len(domain_parts.subdomain.split("."))
            if domain_parts.subdomain else 0
        )

    # URL entropy
    counts = Counter(url)
    entropy = -sum(
        (count / len(url)) * math.log2(count / len(url))
        for count in counts.values()
    )

    # Numeric characters
    digit_count = sum(char.isdigit() for char in url)

    # Token count
    tokens = re.findall(r"[a-zA-Z0-9]+", url)

    # Query parameter count
    query_count = len(
        parse_qsl(parsed.query, keep_blank_values=True)
    )

    features = {
        "url_length": len(url),
        "has_ip_address": has_ip,
        "dot_count": url.count("."),
        "https_flag": int(parsed.scheme.lower() == "https"),
        "url_entropy": entropy,
        "token_count": len(tokens),
        "subdomain_count": subdomain_count,
        "query_param_count": query_count,
        "tld_length": len(tld),
        "path_length": len(parsed.path),
        "has_hyphen_in_domain": int("-" in hostname),
        "number_of_digits": digit_count,
        "tld_popularity": int(
            any(suffix in POPULAR_TLDS for suffix in tld.split("."))
        ),
        "suspicious_file_extension": int(
            any(
                parsed.path.lower().endswith(ext)
                for ext in SUSPICIOUS_EXTENSIONS
            )
        ),
        "domain_name_length": len(domain_name),
        "percentage_numeric_chars": (
            digit_count / len(url) * 100
        )
    }

    return features


if __name__ == "__main__":

    test_url = input("Enter a URL: ").strip()

    try:
        result = extract_features(test_url)

        print("\n========== EXTRACTED FEATURES ==========")

        for name, value in result.items():
            print(f"{name}: {value}")

        print("========================================")

    except ValueError as error:
        print("Error:", error)
