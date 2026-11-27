
import ipaddress
import re
import joblib
import pandas as pd

from urllib.parse import urlparse
from feature_extractor_v2 import extract_features


# ==========================================
# CONFIGURATION
# ==========================================

MODEL_PATH = "model/phishing_model.joblib"

TRUSTED_BRANDS = {
    "google": ["google.com"],
    "paypal": ["paypal.com"],
    "bank": ["bank.com"],
    "amazon": ["amazon.com"],
    "microsoft": ["microsoft.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "allegro": ["allegro.pl", "allegrolokalnie.pl"]
}


# ==========================================
# LOAD TRAINED MODEL
# ==========================================

try:
    model_data = joblib.load(MODEL_PATH)

    model = model_data["model"]
    feature_names = model_data["feature_names"]

except FileNotFoundError:
    print("Error: Trained model not found.")
    print("Please run train_model.py first.")
    raise SystemExit(1)

except (KeyError, ValueError) as error:
    print("Error loading model:", error)
    raise SystemExit(1)


# ==========================================
# BRAND DOMAIN VALIDATION
# ==========================================

def is_official_brand_domain(hostname, official_domains):

    for domain in official_domains:

        if hostname == domain or hostname.endswith("." + domain):
            return True

    return False


# ==========================================
# RULE-BASED DETECTION
# ==========================================

def detect_suspicious_patterns(url):

    suspicious = []

    try:
        parsed = urlparse(
            url if "://" in url else "http://" + url
        )

        hostname = (parsed.hostname or "").lower()

    except ValueError:
        return ["Invalid URL format"]

    if not hostname:
        return ["URL is missing a valid hostname"]

    labels = hostname.split(".")

    # Domain label validation

    for label in labels:

        if len(label) > 63:
            suspicious.append(
                "Domain label exceeds 63 characters"
            )
            break

    for label in labels:

        if label.startswith("-") or label.endswith("-"):
            suspicious.append(
                "Domain label starts or ends with a hyphen"
            )
            break

    if ".." in hostname:
        suspicious.append(
            "Hostname contains consecutive dots"
        )

    if any(char.isspace() for char in hostname):
        suspicious.append(
            "Hostname contains whitespace"
        )

    if not re.fullmatch(r"[a-zA-Z0-9.-]+", hostname):
        suspicious.append(
            "Hostname contains unusual characters"
        )

    # IP address detection

    try:
        ipaddress.ip_address(hostname)

        suspicious.append(
            "Hostname uses an IP address"
        )

    except ValueError:
        pass

    # HTTPS validation

    if parsed.scheme.lower() != "https":
        suspicious.append(
            "URL does not use HTTPS"
        )

    # @ symbol detection

    if "@" in parsed.netloc:
        suspicious.append(
            "URL contains @ in its authority section"
        )

    # Suspicious keywords

    suspicious_keywords = [
        "login", "verify", "secure", "update",
        "account", "signin", "password", "confirm"
    ]

    for keyword in suspicious_keywords:

        if keyword in url.lower():
            suspicious.append(
                f"URL contains suspicious keyword: {keyword}"
            )

    # Hyphen detection

    if "-" in hostname:
        suspicious.append(
            "Hostname contains a hyphen"
        )

    # URL length

    if len(url) > 75:
        suspicious.append(
            "URL is unusually long"
        )

    # Brand impersonation detection

    hostname_labels = hostname.split(".")

    for brand, official_domains in TRUSTED_BRANDS.items():

        brand_found = any(
            brand in label
            for label in hostname_labels[:-1]
        )

        official_domain = is_official_brand_domain(
            hostname,
            official_domains
        )

        if brand_found and not official_domain:

            suspicious.append(
                f"Possible {brand} brand impersonation detected"
            )

    return suspicious


# ==========================================
# MACHINE LEARNING PREDICTION
# ==========================================

def predict_url(url):

    features = extract_features(url)

    feature_values = [
        features[name]
        for name in feature_names
    ]

    input_data = pd.DataFrame(
        [feature_values],
        columns=feature_names
    )

    prediction = int(
        model.predict(input_data)[0]
    )

    probabilities = model.predict_proba(input_data)[0]

    class_probabilities = dict(
        zip(model.classes_, probabilities)
    )

    phishing_probability = (
        float(class_probabilities.get(0, 0)) * 100
    )

    legitimate_probability = (
        float(class_probabilities.get(1, 0)) * 100
    )

    return (
        prediction,
        phishing_probability,
        legitimate_probability,
        features
    )


# ==========================================
# FINAL RISK ASSESSMENT
# ==========================================

def calculate_risk(prediction, suspicious):

    brand_warning = any(
        "brand impersonation" in reason
        for reason in suspicious
    )

    if prediction == 0 or brand_warning:

        return "HIGH"

    elif suspicious:

        return "MEDIUM"

    else:

        return "LOW"


# ==========================================
# MAIN URL CHECKING FUNCTION
# ==========================================

def check_url(url):

    print("\n========== URL SECURITY ANALYSIS ==========")

    print("URL:", url)

    try:

        (
            prediction,
            phishing_probability,
            legitimate_probability,
            features
        ) = predict_url(url)

    except (ValueError, TypeError, KeyError) as error:

        print("\nError:", error)
        return

    suspicious = detect_suspicious_patterns(url)

    # Machine learning result

    print("\n========== MACHINE LEARNING RESULT ==========")

    if prediction == 0:

        print("ML Prediction: PHISHING")

    else:

        print("ML Prediction: LEGITIMATE")

    print(
        f"Phishing Model Score: {phishing_probability:.2f}%"
    )

    print(
        f"Legitimate Model Score: {legitimate_probability:.2f}%"
    )

    # Rule-based result

    print("\n========== RULE-BASED ANALYSIS ==========")

    if suspicious:

        print("Suspicious patterns detected:")

        for reason in suspicious:

            print("-", reason)

    else:

        print("No suspicious patterns detected.")

    # Combined risk

    risk = calculate_risk(
        prediction,
        suspicious
    )

    print("\n========== FINAL RISK ASSESSMENT ==========")

    print("Risk Level:", risk)

    if risk == "HIGH":

        print(
            "WARNING: Potential phishing activity detected."
        )

        print(
            "Avoid entering personal or financial information."
        )

    elif risk == "MEDIUM":

        print(
            "CAUTION: Suspicious indicators found."
        )

        print(
            "Verify the website independently."
        )

    else:

        print(
            "No major warning indicators detected."
        )

        print(
            "This result does not guarantee website safety."
        )

    # Extracted features

    print("\n========== EXTRACTED FEATURES ==========")

    for name, value in features.items():

        print(f"{name}: {value}")

    print("\n============================================")

    print("Analysis completed.")

    print("============================================")


# ==========================================
# MAIN PROGRAM
# ==========================================

if __name__ == "__main__":

    url = input(
        "\nEnter a URL to check: "
    ).strip()

    if not url:

        print("Error: URL cannot be empty.")

    else:

        check_url(url)
