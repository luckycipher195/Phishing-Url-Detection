
from urllib.parse import urlparse


def extract_features(url):

    # Parse the URL
    parsed_url = urlparse(url)

    hostname = parsed_url.hostname or ""

    # Extract basic features
    url_length = len(url)
    hostname_length = len(hostname)
    dot_count = url.count(".")
    hyphen_count = url.count("-")

    # Count subdomains
    parts = hostname.split(".")
    subdomain_count = max(0, len(parts) - 2)

    # Check HTTPS
    is_https = parsed_url.scheme == "https"

    # Count special characters
    special_char_count = sum(
        not char.isalnum() for char in url
    )

    # Store all features
    features = {
        "URL Length": url_length,
        "Hostname Length": hostname_length,
        "Number of Dots": dot_count,
        "Number of Hyphens": hyphen_count,
        "Subdomain Count": subdomain_count,
        "HTTPS": is_https,
        "Special Character Count": special_char_count
    }

    return features


# Main program
if __name__ == "__main__":
    url = input("Enter a URL: ")

    result = extract_features(url)

    print("\n========== EXTRACTED URL FEATURES ==========")

    for feature, value in result.items():
        print(f"{feature}: {value}")

    print("============================================")
