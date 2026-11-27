
import os
import ipaddress
import joblib
import pandas as pd

from urllib.parse import urlsplit
from feature_extractor_v2 import extract_features

from sklearn.model_selection import StratifiedGroupKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# STEP 1: Create output directory

os.makedirs("model", exist_ok=True)

print("Loading dataset...")

df = pd.read_csv("dataset/cleaned_dataset.csv")
df = df.dropna(subset=["URL", "ClassLabel"]).copy()
df["ClassLabel"] = df["ClassLabel"].astype(int)

print("Total URLs:", len(df))


# STEP 2: Extract hostname from URL

def extract_hostname(url):

    url = str(url).strip()

    if not url:
        raise ValueError("Empty URL")

    if "://" not in url:
        url = "http://" + url

    parsed = urlsplit(url)

    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise ValueError("Hostname not found")

    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    return hostname


# STEP 3: Extract features and hostname groups

print("\nExtracting features and hostnames...")

feature_records = []
valid_indices = []
hostname_groups = []

for index, url in enumerate(df["URL"]):

    try:
        features = extract_features(url)
        hostname = extract_hostname(url)

        feature_records.append(features)
        hostname_groups.append(hostname)
        valid_indices.append(index)

    except (ValueError, TypeError):
        continue

    if (index + 1) % 10000 == 0:
        print(f"Processed {index + 1}/{len(df)} URLs")


X = pd.DataFrame(feature_records)

valid_df = df.iloc[valid_indices].reset_index(drop=True)

y = valid_df["ClassLabel"]

groups = pd.Series(hostname_groups)

print("\nValid records:", len(X))
print("Number of features:", X.shape[1])
print("Unique hostnames:", groups.nunique())


# STEP 4: Group-based train-test split

print("\nPerforming hostname-based split...")

splitter = StratifiedGroupKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)

train_indices, test_indices = next(
    splitter.split(X, y, groups=groups)
)

X_train = X.iloc[train_indices]
X_test = X.iloc[test_indices]

y_train = y.iloc[train_indices]
y_test = y.iloc[test_indices]

train_groups = set(groups.iloc[train_indices])
test_groups = set(groups.iloc[test_indices])

overlapping_groups = train_groups.intersection(test_groups)

print("\nTraining records:", len(X_train))
print("Testing records:", len(X_test))

print("\nTraining hostnames:", len(train_groups))
print("Testing hostnames:", len(test_groups))

print("\nOverlapping hostnames:", len(overlapping_groups))

if overlapping_groups:
    raise RuntimeError(
        "Hostname leakage detected!"
    )

print("Hostname leakage check passed!")


# STEP 5: Define models

models = {

    "Decision Tree": DecisionTreeClassifier(
        random_state=42,
        class_weight="balanced"
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    ),

    "Logistic Regression": Pipeline([
        ("scaler", StandardScaler()),
        ("model", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        ))
    ])
}


# STEP 6: Train and evaluate

results = []
reports = {}
confusion_matrices = {}

for name, model in models.items():

    print(f"\n========== {name} ==========")

    print("Training...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    precision = precision_score(
        y_test,
        predictions,
        pos_label=0,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        pos_label=0,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        pos_label=0,
        zero_division=0
    )

    results.append({
        "Model": name,
        "Accuracy": accuracy,
        "Phishing Precision": precision,
        "Phishing Recall": recall,
        "Phishing F1-Score": f1
    })

    reports[name] = classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        zero_division=0
    )

    confusion_matrices[name] = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    )

    print(f"Accuracy: {accuracy:.4f}")
    print(f"Phishing Precision: {precision:.4f}")
    print(f"Phishing Recall: {recall:.4f}")
    print(f"Phishing F1-Score: {f1:.4f}")

    print("\nConfusion Matrix:")
    print(confusion_matrices[name])


# STEP 7: Save comparison

results_df = pd.DataFrame(results)

print("\n========== HOSTNAME VALIDATION RESULTS ==========")
print(results_df.to_string(index=False))

results_df.to_csv(
    "model/hostname_validation_comparison.csv",
    index=False
)


# STEP 8: Save detailed reports

with open(
    "model/hostname_validation_report.txt",
    "w",
    encoding="utf-8"
) as file:

    file.write("HOSTNAME-BASED VALIDATION REPORT\n")
    file.write("================================\n\n")

    file.write(f"Total records: {len(valid_df)}\n")
    file.write(f"Unique hostnames: {groups.nunique()}\n")
    file.write(f"Training records: {len(X_train)}\n")
    file.write(f"Testing records: {len(X_test)}\n")
    file.write(f"Overlapping hostnames: {len(overlapping_groups)}\n")

    for name in models:

        file.write(f"\n========== {name} ==========\n")
        file.write(reports[name])

        file.write("\nConfusion Matrix:\n")
        file.write(str(confusion_matrices[name]))
        file.write("\n")


# STEP 9: Final output

best_model_name = results_df.loc[
    results_df["Phishing F1-Score"].idxmax(),
    "Model"
]

print("\nBest Model:", best_model_name)

print("\nReports saved:")
print("1. model/hostname_validation_comparison.csv")
print("2. model/hostname_validation_report.txt")

print("\nHostname-based validation completed!")
