
import pandas as pd


# Step 1: Load the original dataset
input_file = "dataset/url_features_extracted1.csv"
output_file = "dataset/cleaned_dataset.csv"

print("Loading dataset...")

df = pd.read_csv(input_file)

print("Original records:", len(df))


# Step 2: Check required columns
required_columns = ["URL", "ClassLabel"]

for column in required_columns:
    if column not in df.columns:
        raise ValueError(f"Required column missing: {column}")


# Step 3: Remove rows with missing or empty URLs
df["URL"] = df["URL"].astype("string").str.strip()

df = df.dropna(subset=["URL"])
df = df[df["URL"] != ""]


# Step 4: Convert labels into numeric format
df["ClassLabel"] = pd.to_numeric(
    df["ClassLabel"], errors="coerce"
)

df = df.dropna(subset=["ClassLabel"])


# Step 5: Keep only valid labels
df = df[df["ClassLabel"].isin([0, 1])]

df["ClassLabel"] = df["ClassLabel"].astype(int)


# Step 6: Identify URLs having conflicting labels
label_counts = df.groupby("URL")["ClassLabel"].nunique()

conflicting_urls = label_counts[label_counts > 1].index

print("URLs with conflicting labels:", len(conflicting_urls))

# Remove all rows belonging to conflicting URLs
df = df[~df["URL"].isin(conflicting_urls)]


# Step 7: Remove duplicate URLs
before_duplicates = len(df)

df = df.drop_duplicates(subset=["URL"], keep="first")

duplicates_removed = before_duplicates - len(df)


# Step 8: Check feature columns
feature_columns = [
    column for column in df.columns
    if column not in ["URL", "ClassLabel"]
]

for column in feature_columns:
    df[column] = pd.to_numeric(df[column], errors="coerce")

# Stop if feature values are missing or invalid
if df[feature_columns].isnull().any().any():
    print("\nMissing or invalid feature values detected.")
    print(df[feature_columns].isnull().sum())
    raise ValueError("Please inspect the feature values before proceeding.")


# Step 9: Save the cleaned dataset
df.to_csv(output_file, index=False)


# Step 10: Display cleaning results
print("\n========== DATASET CLEANING REPORT ==========")

print("Final records:", len(df))
print("Duplicate URL rows removed:", duplicates_removed)
print("Conflicting URLs excluded:", len(conflicting_urls))

print("\nClass distribution:")
print("0 = Phishing")
print("1 = Legitimate")
print(df["ClassLabel"].value_counts().sort_index())

print("\nFeature columns:", len(feature_columns))
print("Total columns:", len(df.columns))

print("\nSaved cleaned dataset:", output_file)
print("============================================")
