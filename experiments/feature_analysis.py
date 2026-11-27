import pandas as pd

from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier


# Step 1: Load the cleaned dataset
print("Loading dataset...")

df = pd.read_csv("dataset/cleaned_dataset.csv")

print("Total records:", len(df))


# Step 2: Investigate missing or invalid hostnames
def extract_domain(url):
    try:
        hostname = urlparse(str(url)).hostname
        return hostname.lower() if hostname else None
    except ValueError:
        return None


df["Domain"] = df["URL"].apply(extract_domain)

invalid_domains = df[df["Domain"].isna()]

print("\n========== DOMAIN INVESTIGATION ==========")
print("Records without valid hostnames:", len(invalid_domains))

print("\nSample URLs without valid hostnames:")
print(invalid_domains["URL"].head(10).to_string(index=False))


# Step 3: Prepare features and target
X = df.drop(columns=["URL", "ClassLabel", "Domain"])
y = df["ClassLabel"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# Step 4: Train Random Forest
print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train, y_train)


# Step 5: Calculate feature importance
importance_df = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
})

importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
)

print("\n========== FEATURE IMPORTANCE ==========")
print(importance_df.to_string(index=False))


# Step 6: Check feature-label correlation
correlation_df = df[X.columns].copy()
correlation_df["ClassLabel"] = y

correlations = (
    correlation_df.corr(numeric_only=True)["ClassLabel"]
    .drop("ClassLabel")
    .sort_values(key=abs, ascending=False)
)

print("\n========== FEATURE-LABEL CORRELATION ==========")
print(correlations.to_string())


# Step 7: Save feature analysis
importance_df.to_csv(
    "dataset/feature_importance.csv",
    index=False
)

correlations.to_csv(
    "dataset/feature_correlations.csv",
    header=["Correlation"]
)

print("\nFeature analysis files saved successfully.")
print("\nFeature analysis completed!")