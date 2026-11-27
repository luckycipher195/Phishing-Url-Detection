
import pandas as pd

from feature_extractor_v2 import extract_features

df = pd.read_csv("dataset/url_features_extracted1.csv")

features_to_check = [
    "token_count",
    "query_param_count",
    "tld_popularity"
]

shown = {feature: 0 for feature in features_to_check}

for _, row in df.iterrows():
    extracted = extract_features(row["URL"])

    for feature in features_to_check:
        original = row[feature]
        calculated = extracted[feature]

        if original != calculated and shown[feature] < 5:
            print(f"\nFeature: {feature}")
            print("URL:", row["URL"])
            print("Dataset value:", original)
            print("Our calculated value:", calculated)
            shown[feature] += 1

print("\nMismatch examples completed.")
