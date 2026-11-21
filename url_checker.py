from urllib.parse import urlparse
import ipaddress
import re
from feature_extractor import extract_features
def check_url(url):

    suspicious = []

    try:
        parsed_url = urlparse(url if "://" in url else "http://" + url)
        hostname = parsed_url.hostname or ""
    except ValueError:
        print("Invalid URL format")
        return

    try:
        parsed_url.port
    except ValueError:
        suspicious.append("URL contains an invalid port number")

    if not hostname:
        suspicious.append("URL is missing a hostname")

    labels = hostname.split(".")

    for label in labels:
        if len(label) > 63:
            suspicious.append("Domain label exceeds 63 characters")
            break

    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            suspicious.append("Domain label starts or ends with a hyphen")
            break

    if hostname:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            if not re.fullmatch(r"[a-zA-Z0-9.-]+", hostname):
                suspicious.append("Hostname contains invalid characters")

    if ".." in hostname:
        suspicious.append("Hostname contains consecutive dots")

    if hostname.startswith("."):
        suspicious.append("Hostname starts with a dot")

    if hostname.endswith("."):
        suspicious.append("Hostname ends with a dot")

    if " " in hostname:
        suspicious.append("Hostname contains spaces")
    try:
        ipaddress.ip_address(hostname)
        suspicious.append("Hostname is an IP address instead of a domain name")
    except ValueError:
        pass

    if parsed_url.scheme != "https":
        suspicious.append("URL does not use HTTPS")

    if "@" in parsed_url.netloc:
        suspicious.append("Contains @ in the URL authority section")
    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "signin",
        "password",
        "confirm"
        ]
    for keyword in suspicious_keywords:
         if keyword in url.lower():
            suspicious.append(
                f"URL contains suspicious keyword: {keyword}"
            )     
    if "-" in hostname and not any(
        label.startswith("-") or label.endswith("-") for label in labels
    ):
        suspicious.append("Hostname contains a hyphen")
    if len(url) > 75:
        suspicious.append("URL is unusually long")

    # Demonstration rule: detect misleading bank.com text 
    trusted_brands = {
       "bank": "bank.com",
       "paypal": "paypal.com",
       "google": "google.com"
    }

    for brand, domain in trusted_brands.items():
        if brand in hostname.split(".")[0].split("-") and not (
            hostname == domain or hostname.endswith("." + domain)
        ):
            suspicious.append(
                f"Possible {brand} brand impersonation detected"
            )
    if suspicious:
        print("\nPotentially suspicious URL")
        for reason in suspicious:
            print("-", reason)
    else:
        print("\nNo suspicious patterns detected by these basic rules")
    features = extract_features(url)

    print("\n========== EXTRACTED URL FEATURES ==========")

    for feature, value in features.items():
        print(f"{feature}: {value}")

    print("============================================")
# Main program
# Main program
if __name__ == "__main__":
    url = input("Enter a URL to check: ").strip()

    if not url:
        print("Error: URL cannot be empty.")
    else:
        check_url(url)