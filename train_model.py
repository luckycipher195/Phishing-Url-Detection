
import os
import joblib
import pandas as pd

from urllib.parse import urlsplit, urlunsplit
from feature_extractor_v2 import extract_features

from sklearn.model_selection import StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
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


# STEP 1: Create output folder

os.makedirs("model", exist_ok=True)

print("Loading dataset...")

df = pd.read_csv("dataset/cleaned_dataset.csv")
df = df.dropna(subset=["URL", "ClassLabel"]).copy()

df["ClassLabel"] = df["ClassLabel"].astype(int)

print("Total URLs:", len(df))


# STEP 2: Normalize URLs for grouping

def normalize_url(url):

    url = str(url).strip()

    if not url:
        return ""

    if "://" not in url:
        url = "http://" + url

    try:
        parsed = urlsplit(url)

        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            return url.lower()

        port = parsed.port

        if port and not (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        ):
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        return urlunsplit((
            scheme,
            netloc,
            parsed.path or "/",
            parsed.query,
            ""
        ))

    except ValueError:
        return url.lower()


df["normalized_url"] = df["URL"].apply(normalize_url)


# STEP 3: Extract features

print("\nExtracting features from URLs...")

feature_records = []
valid_indices = []

for index, url in enumerate(df["URL"]):

    try:
        features = extract_features(url)

        feature_records.append(features)
        valid_indices.append(index)

    except (ValueError, TypeError):
        continue

    if (index + 1) % 10000 == 0:
        print(f"Processed {index + 1}/{len(df)} URLs")


X = pd.DataFrame(feature_records)

valid_df = df.iloc[valid_indices].reset_index(drop=True)

y = valid_df["ClassLabel"]

groups = valid_df["normalized_url"]

print("\nValid records:", len(X))
print("Number of features:", X.shape[1])
print("Unique URL groups:", groups.nunique())


# STEP 4: Group-based stratified split

print("\nPerforming group-based train-test split...")

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

print("\nTraining class distribution:")
print(y_train.value_counts().sort_index())

print("\nTesting class distribution:")
print(y_test.value_counts().sort_index())

print("\nOverlapping URL groups:", len(overlapping_groups))

if overlapping_groups:
    raise RuntimeError(
        "Data leakage detected! URL groups overlap."
    )

print("Group leakage check passed!")


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


# STEP 6: Train and evaluate models

results = []
trained_models = {}
evaluation_reports = {}

for name, model in models.items():

    print(f"\n========== {name} ==========")

    print("Training...")
    model.fit(X_train, y_train)

    print("Predicting...")
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

    trained_models[name] = model

    report = classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        zero_division=0
    )

    evaluation_reports[name] = report

    print(f"Accuracy: {accuracy:.4f}")
    print(f"Phishing Precision: {precision:.4f}")
    print(f"Phishing Recall: {recall:.4f}")
    print(f"Phishing F1-Score: {f1:.4f}")

    print("\nClassification Report:")
    print(report)

    print("\nConfusion Matrix:")
    print(confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    ))


# STEP 7: Save model comparison

results_df = pd.DataFrame(results)

print("\n========== MODEL COMPARISON ==========")
print(results_df.to_string(index=False))

results_df.to_csv(
    "model/model_comparison.csv",
    index=False
)


# STEP 8: Select best model

best_model_name = results_df.loc[
    results_df["Phishing F1-Score"].idxmax(),
    "Model"
]

best_model = trained_models[best_model_name]

print("\nBest model:", best_model_name)


# STEP 9: Generate best model evaluation

best_predictions = best_model.predict(X_test)

best_report = classification_report(
    y_test,
    best_predictions,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"],
    zero_division=0
)

best_matrix = confusion_matrix(
    y_test,
    best_predictions,
    labels=[0, 1]
)

confusion_df = pd.DataFrame(
    best_matrix,
    index=["Actual Phishing", "Actual Legitimate"],
    columns=["Predicted Phishing", "Predicted Legitimate"]
)

confusion_df.to_csv(
    "model/confusion_matrix.csv"
)


# STEP 10: Save evaluation reports

with open(
    "model/classification_report.txt",
    "w",
    encoding="utf-8"
) as file:

    file.write(f"Best Model: {best_model_name}\n")
    file.write("Evaluation: Stratified Group-Based Split\n\n")
    file.write(best_report)


with open(
    "model/all_model_reports.txt",
    "w",
    encoding="utf-8"
) as file:

    file.write("Evaluation: Stratified Group-Based Split\n")

    for name, report in evaluation_reports.items():

        file.write(f"\n========== {name} ==========\n")
        file.write(report)
        file.write("\n")


# STEP 11: Save trained model

model_data = {
    "model": best_model,
    "model_name": best_model_name,
    "feature_names": X.columns.tolist(),
    "label_map": {
        0: "Phishing",
        1: "Legitimate"
    }
}

joblib.dump(
    model_data,
    "model/phishing_model.joblib"
)


# STEP 12: Final output

print("\n========== FINAL EVALUATION ==========")

print("Best Model:", best_model_name)

print("\nBest Model Classification Report:")
print(best_report)

print("\nBest Model Confusion Matrix:")
print(confusion_df)

print("\n========== FILES SAVED ==========")
print("1. model/phishing_model.joblib")
print("2. model/model_comparison.csv")
print("3. model/confusion_matrix.csv")
print("4. model/classification_report.txt")
print("5. model/all_model_reports.txt")

print("\nGroup-based training and evaluation completed!")
