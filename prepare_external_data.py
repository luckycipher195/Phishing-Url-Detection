
import pandas as pd
import tldextract

from urllib.parse import urlsplit
import ipaddress
import os

os.makedirs("external_data/processed", exist_ok=True)

extractor = tldextract.TLDExtract(suffix_list_urls=())


def get_domain(value):

    value = str(value).strip()

    if not value:
        return None

    if "://" not in value:
        value = "http://" + value

    hostname = (urlsplit(value).hostname or "").lower()

    if not hostname:
        return None

    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    result = extractor(hostname)

    if result.top_domain_under_public_suffix:
        return result.top_domain_under_public_suffix.lower()

    return hostname


print("Loading datasets...")

phish = pd.read_csv("external_data/phishtank.csv")
tranco = pd.read_csv(
    "external_data/tranco.csv",
    header=None,
    names=["rank", "domain"]
)
train = pd.read_csv("dataset/cleaned_dataset.csv")


# Prepare PhishTank
phish = phish[
    (phish["verified"].astype(str).str.lower() == "yes") &
    (phish["online"].astype(str).str.lower() == "yes")
].copy()

phish = phish.dropna(subset=["url"])
phish = phish.drop_duplicates(subset=["url"])

phish["domain"] = phish["url"].apply(get_domain)
phish = phish.dropna(subset=["domain"])


# Prepare Tranco
tranco = tranco.dropna(subset=["domain"]).copy()
tranco["domain"] = tranco["domain"].astype(str).str.lower().str.strip()

tranco["domain"] = tranco["domain"].apply(get_domain)
tranco = tranco.dropna(subset=["domain"])
tranco = tranco.drop_duplicates(subset=["domain"])


# Get training domains
train_domains = set(
    train["URL"].dropna().apply(get_domain).dropna()
)

phish_domains = set(phish["domain"])
tranco_domains = set(tranco["domain"])


# Find cross-source domain conflicts
cross_source_overlap = phish_domains.intersection(tranco_domains)

print("\n========== OVERLAP ANALYSIS ==========")

print("Training domains:", len(train_domains))
print("PhishTank domains:", len(phish_domains))
print("Tranco domains:", len(tranco_domains))

print("PhishTank-training overlap:",
      len(phish_domains.intersection(train_domains)))

print("Tranco-training overlap:",
      len(tranco_domains.intersection(train_domains)))

print("PhishTank-Tranco overlap:",
      len(cross_source_overlap))


# Remove training overlap
clean_phish = phish[
    ~phish["domain"].isin(train_domains)
].copy()

clean_tranco = tranco[
    ~tranco["domain"].isin(train_domains)
].copy()


# Remove domains appearing in both external sources
clean_phish = clean_phish[
    ~clean_phish["domain"].isin(cross_source_overlap)
].copy()

clean_tranco = clean_tranco[
    ~clean_tranco["domain"].isin(cross_source_overlap)
].copy()


# Final verification
final_phish_domains = set(clean_phish["domain"])
final_tranco_domains = set(clean_tranco["domain"])

assert not final_phish_domains.intersection(train_domains)
assert not final_tranco_domains.intersection(train_domains)
assert not final_phish_domains.intersection(final_tranco_domains)


# Save clean external candidates
clean_phish.to_csv(
    "external_data/processed/clean_phishtank.csv",
    index=False
)

clean_tranco.to_csv(
    "external_data/processed/clean_tranco.csv",
    index=False
)


print("\n========== CLEAN DATASET SUMMARY ==========")

print("Original PhishTank URLs:", len(phish))
print("Clean PhishTank URLs:", len(clean_phish))
print("Clean PhishTank domains:", len(final_phish_domains))

print("\nOriginal Tranco domains:", len(tranco))
print("Clean Tranco domains:", len(clean_tranco))

print("\nTraining overlap remaining:",
      len(final_phish_domains.intersection(train_domains)) +
      len(final_tranco_domains.intersection(train_domains)))

print("Cross-source overlap remaining:",
      len(final_phish_domains.intersection(final_tranco_domains)))

print("\nClean external datasets saved successfully!")
