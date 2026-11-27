
import pandas as pd
import tldextract

from urllib.parse import urlsplit

PHISHTANK_FILE = "external_data/phishtank.csv"
TRANCO_FILE = "external_data/tranco.csv"
TRAIN_FILE = "dataset/cleaned_dataset.csv"

extractor = tldextract.TLDExtract(suffix_list_urls=())


def get_domain(url):

    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    hostname = (urlsplit(url).hostname or "").lower()

    if not hostname:
        return None

    result = extractor(hostname)

    if result.top_domain_under_public_suffix:
        return result.top_domain_under_public_suffix.lower()

    return hostname


print("Loading external datasets...")

phish = pd.read_csv(PHISHTANK_FILE)
tranco = pd.read_csv(TRANCO_FILE, header=None, names=["rank", "domain"])

train = pd.read_csv(TRAIN_FILE)

print("\n========== PHISHTANK QUALITY ==========")

print("Total rows:", len(phish))
print("\nVerification counts:")
print(phish["verified"].value_counts(dropna=False))

print("\nOnline counts:")
print(phish["online"].value_counts(dropna=False))

verified_phish = phish[
    (phish["verified"].astype(str).str.lower() == "yes") &
    (phish["online"].astype(str).str.lower() == "yes")
].copy()

verified_phish = verified_phish.dropna(subset=["url"])
verified_phish = verified_phish.drop_duplicates(subset=["url"])

verified_phish["domain"] = verified_phish["url"].apply(get_domain)
verified_phish = verified_phish.dropna(subset=["domain"])

print("\nVerified and online phishing URLs:", len(verified_phish))
print("Unique phishing URLs:", verified_phish["url"].nunique())
print("Unique phishing domains:", verified_phish["domain"].nunique())

print("\n========== TRANCO QUALITY ==========")

tranco = tranco.dropna(subset=["domain"])
tranco["domain"] = tranco["domain"].astype(str).str.lower().str.strip()
tranco = tranco.drop_duplicates(subset=["domain"])

print("Total Tranco domains:", len(tranco))
print("\nSample domains:")
print(tranco.head(10).to_string(index=False))

print("\n========== TRAINING DATA OVERLAP ==========")

train_domains = set(
    train["URL"].dropna().apply(get_domain).dropna()
)

phish_domains = set(verified_phish["domain"])
tranco_domains = set(tranco["domain"].apply(get_domain).dropna())

phish_overlap = phish_domains.intersection(train_domains)
tranco_overlap = tranco_domains.intersection(train_domains)

print("Unique training domains:", len(train_domains))
print("PhishTank domains overlapping training:", len(phish_overlap))
print("Tranco domains overlapping training:", len(tranco_overlap))

print("\n========== SUMMARY ==========")

print("PhishTank candidate URLs:", len(verified_phish))
print("PhishTank candidate domains:", len(phish_domains))
print("Tranco candidate domains:", len(tranco_domains))

print("\nExternal dataset inspection completed.")
