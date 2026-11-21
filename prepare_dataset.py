
import pandas as pd
from feature_extractor import extract_features


# Step 1: Load the phishing dataset
input_file = "dataset/verified_online.csv"

print("Loading phishing dataset...")

df = pd.read_csv(input_file)

print("Original records:", len(df))


# Step 2: Keep only verified and online phishing URLs
df = df[
    (df["verified"].str.lower() == "yes") &
    (df["online"].str.lower() == "yes")
]


# Step 3: Remove empty and duplicate URLs
df = df.dropna(subset=["url"])

df["url"] = df["url"].astype(str).str.strip()

df = df[df["url"] != ""]

df = df.drop_duplicates(subset=["url"])

print("Records after cleaning:", len(df))


# Step 4: Extract features from each URL
print("Extracting URL features...")

feature_list = []

for url in df["url"]:
    features = extract_features(url)
    feature_list.append(features)


# Step 5: Convert extracted features into a DataFrame
features_df = pd.DataFrame(feature_list)


# Step 6: Assign phishing label
features_df["label"] = 1


# Step 7: Save the processed dataset
output_file = "dataset/processed_phishing.csv"

features_df.to_csv(output_file, index=False)

print("\nDataset preparation completed!")
print("Total phishing records:", len(features_df))
print("Saved file:", output_file)

print("\nExtracted feature columns:")
print(features_df.columns.tolist())
