from urllib.parse import urlparse
import ipaddress
import re
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
    if "-" in hostname and not any(
        label.startswith("-") or label.endswith("-") for label in labels
    ):
        suspicious.append("Hostname contains a hyphen")
    if len(url) > 75:
        suspicious.append("URL is unusually long")

    # Demonstration rule: detect misleading bank.com text
    
    trusted_domains = ["bank.com", "paypal.com", "google.com"]

    for domain in trusted_domains:
        if domain in hostname and not (
            hostname == domain or hostname.endswith("." + domain)
       ):
            suspicious.append(
                f"Contains {domain} text but the hostname is not {domain}"
         )

    if suspicious:
        print("\nPotentially suspicious URL")
        for reason in suspicious:
            print("-", reason)
    else:
        print("\nNo suspicious patterns detected by these basic rules")
url = input("Enter a URL to check: ").strip()

if not url:
    print("Error: URL cannot be empty.")
else:
    check_url(url)
