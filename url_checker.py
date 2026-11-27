
import ipaddress
import re
import joblib

from urllib.parse import urlparse
from feature_extractor_v2 import extract_features


# Load the trained machine-learning model

MODEL_PATH = "model/phishing_model.joblib"

try:
    model_data = joblib.load(MODEL_PATH)
    model = model_data["model"]
    feature_names = model_data["feature_names"]

except FileNotFoundError:
    print("Error: Trained model not found.")
    print("Please run train_model.py first.")
    raise SystemExit(1)


# Rule-based detection

def detect_suspicious_patterns(url):

    suspicious = []

    try:
        parsed = urlparse(
            url if "://" in url else "http://" + url
        )
        hostname = parsed.hostname or ""

    except ValueError:
        return ["Invalid URL format"]

    if not hostname:
        suspicious.append("URL is missing a hostname")
        return suspicious

    labels = hostname.split(".")

    # Domain validation

    for label in labels:
        if len(label) > 63:
            suspicious.append("Domain label exceeds 63 characters")
            break

    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            suspicious.append(
                "Domain label starts or ends with a hyphen"
            )
            break

    if ".." in hostname:
        suspicious.append("Hostname contains consecutive dots")

    if " " in hostname:
        suspicious.append("Hostname contains spaces")

    if not re.fullmatch(r"[a-zA-Z0-9.-]+", hostname):
        suspicious.append("Hostname contains invalid characters")

    # IP address detection

    try:
        ipaddress.ip_address(hostname)
        suspicious.append(
            "Hostname is an IP address instead of a domain name"
        )
    except ValueError:
        pass

    # HTTPS check

    if parsed.scheme.lower() != "https":
        suspicious.append("URL does not use HTTPS")

    # @ symbol detection

    if "@" in parsed.netloc:
        suspicious.append(
            "Contains @ in the URL authority section"
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

    if "-" in hostname and not any(
        label.startswith("-") or label.endswith("-")
        for label in labels
    ):
        suspicious.append("Hostname contains a hyphen")

    # URL length

    if len(url) > 75:
        suspicious.append("URL is unusually long")

    # Brand impersonation detection

    trusted_brands = {
        "bank": "bank.com",
        "paypal": "paypal.com",
        "google": "google.com"
    }

    for brand, domain in trusted_brands.items():

        brand_found = brand in hostname.split(".")[0].split("-")

        legitimate_domain = (
            hostname == domain
            or hostname.endswith("." + domain)
        )

        if brand_found and not legitimate_domain:
            suspicious.append(
                f"Possible {brand} brand impersonation detected"
            )

    return suspicious


# Machine-learning prediction

def predict_url(url):

    features = extract_features(url)

    # Maintain the exact feature order used during training

    feature_values = [
        features[name] for name in feature_names
    ]

    import pandas as pd

    input_data = pd.DataFrame(
        [feature_values],
        columns=feature_names
    )

    prediction = int(model.predict(input_data)[0])

    probabilities = model.predict_proba(input_data)[0]

    class_probabilities = dict(
        zip(model.classes_, probabilities)
    )

    phishing_probability = float(
        class_probabilities.get(0, 0)
    ) * 100

    legitimate_probability = float(
        class_probabilities.get(1, 0)
    ) * 100

    return (
        prediction,
        phishing_probability,
        legitimate_probability,
        features
    )


# Main URL checking function

def check_url(url):

    print("\n========== URL SECURITY ANALYSIS ==========")
    print("URL:", url)

    try:
        prediction, phishing_prob, legitimate_prob, features = (
            predict_url(url)
        )

    except (ValueError, TypeError) as error:
        print("\nError:", error)
        return

    suspicious = detect_suspicious_patterns(url)

    print("\n========== MACHINE LEARNING RESULT ==========")

    if prediction == 0:
        print("ML Prediction: PHISHING")
    else:
        print("ML Prediction: LEGITIMATE")

    print(f"Phishing Probability: {phishing_prob:.2f}%")
    print(f"Legitimate Probability: {legitimate_prob:.2f}%")

    print("\n========== RULE-BASED ANALYSIS ==========")

    if suspicious:
        print("Suspicious patterns detected:")

        for reason in suspicious:
            print("-", reason)

    else:
        print("No suspicious patterns detected by basic rules.")

    # Combined assessment

    print("\n========== FINAL RISK ASSESSMENT ==========")

    if prediction == 0:
        print("RESULT: POTENTIAL PHISHING URL")
        print("WARNING: Avoid entering personal information.")

    elif suspicious:
        print("RESULT: SUSPICIOUS URL")
        print("WARNING: Review the detected warning signs.")

    else:
        print("RESULT: NO MAJOR WARNING DETECTED")
        print("Still verify the website before sharing information.")

    # Display extracted features

    print("\n========== EXTRACTED FEATURES ==========")

    for name, value in features.items():
        print(f"{name}: {value}")

    print("\n============================================")
    print("Analysis completed.")
    print("============================================")


# Main program

if __name__ == "__main__":

    url = input("\nEnter a URL to check: ").strip()

    if not url:
        print("Error: URL cannot be empty.")

    else:
        check_url(url)
