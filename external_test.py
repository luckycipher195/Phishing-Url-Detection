
import os
import joblib
import pandas as pd

from feature_extractor_v2 import extract_features

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# ==========================================
# 1. FILE PATHS
# ==========================================

MODEL_PATH = "model/phishing_model.joblib"

PHISHTANK_PATH = "external_data/processed/clean_phishtank.csv"

TRANCO_PATH = "external_data/processed/clean_tranco.csv"

OUTPUT_DIR = "model/external_test"

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ==========================================
# 2. LOAD TRAINED MODEL
# ==========================================

print("\nLoading trained model...")

saved_data = joblib.load(MODEL_PATH)

model = saved_data["model"]
expected_features = saved_data["feature_names"]

print("Model:", saved_data["model_name"])
print("Expected features:", len(expected_features))


# ==========================================
# 3. LOAD EXTERNAL DATASETS
# ==========================================

print("\nLoading external datasets...")

phish_df = pd.read_csv(PHISHTANK_PATH)
tranco_df = pd.read_csv(TRANCO_PATH)

print("PhishTank records:", len(phish_df))
print("Tranco records:", len(tranco_df))


# ==========================================
# 4. PREPARE PHISHTANK DATA
# ==========================================

print("\nPreparing PhishTank data...")

phish_df = phish_df.dropna(
    subset=["url", "domain"]
).copy()

phish_df["url"] = (
    phish_df["url"].astype(str).str.strip()
)

phish_df["domain"] = (
    phish_df["domain"].astype(str).str.strip().str.lower()
)

phish_df = phish_df[
    (phish_df["url"] != "") &
    (phish_df["domain"] != "")
]

# One URL per domain
phish_df = phish_df.drop_duplicates(
    subset="domain",
    keep="first"
)

print("Unique PhishTank domains:", len(phish_df))


# ==========================================
# 5. PREPARE TRANCO DATA
# ==========================================

print("\nPreparing Tranco data...")

tranco_df = tranco_df.dropna(
    subset=["domain"]
).copy()

tranco_df["domain"] = (
    tranco_df["domain"]
    .astype(str)
    .str.strip()
    .str.lower()
)

tranco_df = tranco_df[
    tranco_df["domain"] != ""
]

tranco_df = tranco_df.drop_duplicates(
    subset="domain"
)

# Remove domains that appear in both datasets
phish_domains = set(phish_df["domain"])

tranco_df = tranco_df[
    ~tranco_df["domain"].isin(phish_domains)
].copy()

print("Unique Tranco candidates:", len(tranco_df))


# ==========================================
# 6. CREATE BALANCED TEST DATASET
# ==========================================

test_size = min(
    len(phish_df),
    len(tranco_df)
)

if test_size == 0:
    raise ValueError(
        "Not enough records to create external test dataset."
    )

# Reproducible random sampling
tranco_test = tranco_df.sample(
    n=test_size,
    random_state=42
)

phishing_records = []

for _, row in phish_df.iterrows():

    phishing_records.append({
        "url": row["url"],
        "domain": row["domain"],
        "actual_label": 0,
        "source": "PhishTank"
    })


tranco_records = []

for _, row in tranco_test.iterrows():

    domain = row["domain"]

    tranco_records.append({
        "url": "https://" + domain + "/",
        "domain": domain,
        "actual_label": 1,
        "source": "Tranco"
    })


test_df = pd.DataFrame(
    phishing_records + tranco_records
)

test_df = test_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)


print("\n========== TEST DATASET ==========")

print("PhishTank phishing URLs:", len(phishing_records))
print("Tranco candidate URLs:", len(tranco_records))
print("Total test URLs:", len(test_df))


# ==========================================
# 7. EXTRACT FEATURES
# ==========================================

print("\nExtracting URL features...")

feature_rows = []
valid_indices = []

for index, row in test_df.iterrows():

    try:

        features = extract_features(row["url"])

        feature_rows.append(features)
        valid_indices.append(index)

    except (ValueError, TypeError) as error:

        print("\nSkipped URL:", row["url"])
        print("Reason:", error)


test_df = test_df.loc[
    valid_indices
].reset_index(drop=True)

X = pd.DataFrame(feature_rows)

if X.empty:
    raise ValueError("No valid URLs available for testing.")


# ==========================================
# 8. MATCH MODEL FEATURE ORDER
# ==========================================

missing_features = [
    feature
    for feature in expected_features
    if feature not in X.columns
]

extra_features = [
    feature
    for feature in X.columns
    if feature not in expected_features
]

if missing_features or extra_features:

    raise ValueError(
        f"Feature mismatch. Missing: {missing_features}; "
        f"Extra: {extra_features}"
    )

X = X[expected_features]

y_true = test_df["actual_label"]

print("\nValid test URLs:", len(X))
print("Features matched:", len(expected_features))


# ==========================================
# 9. MODEL PREDICTION
# ==========================================

print("\nRunning model predictions...")

y_pred = model.predict(X)

test_df["predicted_label"] = y_pred

test_df["prediction"] = test_df["predicted_label"].map({
    0: "Phishing",
    1: "Legitimate"
})


# ==========================================
# 10. OVERALL EVALUATION
# ==========================================

accuracy = accuracy_score(y_true, y_pred)

precision = precision_score(
    y_true,
    y_pred,
    pos_label=0,
    zero_division=0
)

recall = recall_score(
    y_true,
    y_pred,
    pos_label=0,
    zero_division=0
)

f1 = f1_score(
    y_true,
    y_pred,
    pos_label=0,
    zero_division=0
)

cm = confusion_matrix(
    y_true,
    y_pred,
    labels=[0, 1]
)

report = classification_report(
    y_true,
    y_pred,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate candidate"],
    zero_division=0
)


# ==========================================
# 11. SOURCE-WISE RESULTS
# ==========================================

print("\n========== SOURCE-WISE RESULTS ==========")

source_results = []

for source in ["PhishTank", "Tranco"]:

    source_df = test_df[
        test_df["source"] == source
    ]

    total = len(source_df)

    detected = (
        source_df["predicted_label"] == 0
    ).sum()

    classified_legitimate = (
        source_df["predicted_label"] == 1
    ).sum()

    detection_rate = (
        detected / total * 100
        if total else 0
    )

    source_results.append({
        "Source": source,
        "Total": total,
        "Predicted Phishing": detected,
        "Predicted Legitimate": classified_legitimate,
        "Predicted Phishing %": round(detection_rate, 2)
    })

    print(f"\n{source}")
    print("Total:", total)
    print("Predicted Phishing:", detected)
    print("Predicted Legitimate:", classified_legitimate)
    print(f"Predicted Phishing %: {detection_rate:.2f}%")


source_results_df = pd.DataFrame(source_results)


# ==========================================
# 12. DISPLAY OVERALL RESULTS
# ==========================================

print("\n========== EXTERNAL TEST RESULTS ==========")

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")

print("\nConfusion Matrix")
print("Rows = Actual, Columns = Predicted")
print("Order: Phishing (0), Tranco candidate (1)")
print(cm)

print("\nClassification Report")
print(report)


# ==========================================
# 13. SAVE PREDICTIONS
# ==========================================

prediction_path = os.path.join(
    OUTPUT_DIR,
    "external_predictions.csv"
)

test_df.to_csv(
    prediction_path,
    index=False
)


# ==========================================
# 14. SAVE SOURCE-WISE RESULTS
# ==========================================

source_path = os.path.join(
    OUTPUT_DIR,
    "source_wise_results.csv"
)

source_results_df.to_csv(
    source_path,
    index=False
)


# ==========================================
# 15. SAVE EVALUATION REPORT
# ==========================================

report_path = os.path.join(
    OUTPUT_DIR,
    "external_test_report.txt"
)

with open(
    report_path,
    "w",
    encoding="utf-8"
) as file:

    file.write("EXTERNAL DATASET EVALUATION REPORT\n")
    file.write("==================================\n\n")

    file.write(
        "Note: Tranco domains are popularity-ranked "
        "candidates, not verified legitimate URLs.\n\n"
    )

    file.write(f"Total valid test URLs: {len(test_df)}\n")

    file.write(
        f"Phishing URLs: {(y_true == 0).sum()}\n"
    )

    file.write(
        f"Tranco candidate URLs: {(y_true == 1).sum()}\n\n"
    )

    file.write(f"Accuracy : {accuracy:.4f}\n")
    file.write(f"Precision: {precision:.4f}\n")
    file.write(f"Recall   : {recall:.4f}\n")
    file.write(f"F1 Score : {f1:.4f}\n\n")

    file.write("Confusion Matrix:\n")
    file.write(str(cm))

    file.write("\n\nClassification Report:\n")
    file.write(report)

    file.write("\n\nSource-wise Results:\n")
    file.write(source_results_df.to_string(index=False))


# ==========================================
# 16. COMPLETION
# ==========================================

print("\n========== FILES SAVED ==========")

print("1.", prediction_path)
print("2.", source_path)
print("3.", report_path)

print("\nExternal testing completed successfully!")
