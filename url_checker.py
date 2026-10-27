
from urllib.parse import urlparse

def check_url(url):
    suspicious = []

    parsed_url = urlparse(url if "://" in url else "http://" + url)
    hostname = parsed_url.hostname or ""

    if parsed_url.scheme != "https":
        suspicious.append("URL does not use HTTPS")

    if "@" in parsed_url.netloc:
        suspicious.append("Contains @ in the URL authority section")

    if "-" in hostname:
        suspicious.append("Hostname contains a hyphen")

    if len(url) > 75:
        suspicious.append("URL is unusually long")

    # Demonstration rule: detect misleading bank.com text
    if "bank.com" in hostname and not (
        hostname == "bank.com" or hostname.endswith(".bank.com")
    ):
        suspicious.append(
            "Contains bank.com text but the hostname is not bank.com"
        )

    if suspicious:
        print("\nPotentially suspicious URL")
        for reason in suspicious:
            print("-", reason)
    else:
        print("\nNo suspicious patterns detected by these basic rules")

url = input("Enter a URL to check: ").strip()
check_url(url)
