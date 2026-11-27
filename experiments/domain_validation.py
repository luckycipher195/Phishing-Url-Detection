import pandas as pd
import tldextract
from urllib.parse import urlparse
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
# Initialise the domain extractor only once
extractor = tldextract.TLDExtract(suffix_list_urls=())
# Step 1: Load the cleaned dataset
print("Loading cleaned dataset...")

df = pd.read_csv("dataset/cleaned_dataset.csv")


# Step 2: Extract hostname from each URL
def extract_domain(url):
    try:
        url = str(url).strip()
        parsed = urlparse(url)

        if not parsed.hostname:
            parsed = urlparse("//" + url)

        hostname = parsed.hostname

        if not hostname:
            return None

        extracted = extractor(hostname)

        if extracted.domain and extracted.suffix:
            return extracted.top_domain_under_public_suffix

        return hostname.lower()

    except ValueError:
        return None

df["Domain"] = df["URL"].apply(extract_domain)

# Remove records with invalid or missing domains
df = df.dropna(subset=["Domain"]).copy()


# Step 3: Prepare features and labels
X = df.drop(columns=["URL", "ClassLabel", "Domain"])
y = df["ClassLabel"]
groups = df["Domain"]

print("Total records:", len(df))
print("Unique domains:", groups.nunique())
print("Total features:", X.shape[1])


# Step 4: Split data by domain
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_index, test_index = next(
    splitter.split(X, y, groups=groups)
)

X_train = X.iloc[train_index]
X_test = X.iloc[test_index]

y_train = y.iloc[train_index]
y_test = y.iloc[test_index]

train_domains = set(groups.iloc[train_index])
test_domains = set(groups.iloc[test_index])


# Step 5: Verify domain separation
overlap = train_domains.intersection(test_domains)

print("\n========== DOMAIN SPLIT CHECK ==========")
print("Training records:", len(X_train))
print("Testing records:", len(X_test))
print("Training domains:", len(train_domains))
print("Testing domains:", len(test_domains))
print("Overlapping domains:", len(overlap))


# Step 6: Train Random Forest
print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train, y_train)


# Step 7: Make predictions
print("Evaluating model...")

y_pred = model.predict(X_test)


# Step 8: Calculate performance
print("\n========== DOMAIN-BASED RESULTS ==========")

print("Accuracy:", accuracy_score(y_test, y_pred))

print(
    "Phishing Precision:",
    precision_score(y_test, y_pred, pos_label=0, zero_division=0)
)

print(
    "Phishing Recall:",
    recall_score(y_test, y_pred, pos_label=0, zero_division=0)
)

print(
    "Phishing F1-Score:",
    f1_score(y_test, y_pred, pos_label=0, zero_division=0)
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        zero_division=0
    )
)

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred, labels=[0, 1]))

print("\nDomain-based evaluation completed!")
