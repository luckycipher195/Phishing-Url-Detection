
import os
import joblib
import pandas as pd

from feature_extractor_v2 import extract_features


# ==========================================
# 1. FILE PATHS
# ==========================================

MODEL_PATH = "model/phishing_model.joblib"

PREDICTIONS_PATH = (
    "model/external_test/external_predictions.csv"
)

OUTPUT_DIR = "model/error_analysis"

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ==========================================
# 2. LOAD MODEL AND PREDICTIONS
# ==========================================

print("\nLoading trained model...")

saved_data = joblib.load(MODEL_PATH)

model = saved_data["model"]

print("Model:", saved_data["model_name"])

print("\nLoading external predictions...")

df = pd.read_csv(PREDICTIONS_PATH)

print("Total records:", len(df))


# ==========================================
# 3. IDENTIFY INCORRECT PREDICTIONS
# ==========================================

df["actual_label"] = df["actual_label"].astype(int)

df["predicted_label"] = df["predicted_label"].astype(int)

errors = df[
    df["actual_label"] != df["predicted_label"]
].copy()

false_positives = errors[
    (errors["actual_label"] == 1) &
    (errors["predicted_label"] == 0)
].copy()

false_negatives = errors[
    (errors["actual_label"] == 0) &
    (errors["predicted_label"] == 1)
].copy()


print("\n========== ERROR SUMMARY ==========")

print("Total incorrect predictions:", len(errors))

print("False Positives:", len(false_positives))

print("False Negatives:", len(false_negatives))


# ==========================================
# 4. SAVE INCORRECT PREDICTIONS
# ==========================================

errors.to_csv(
    os.path.join(OUTPUT_DIR, "all_errors.csv"),
    index=False
)

false_positives.to_csv(
    os.path.join(OUTPUT_DIR, "false_positives.csv"),
    index=False
)

false_negatives.to_csv(
    os.path.join(OUTPUT_DIR, "false_negatives.csv"),
    index=False
)


# ==========================================
# 5. DISPLAY SAMPLE ERRORS
# ==========================================

print("\n========== FALSE POSITIVE SAMPLES ==========")

if len(false_positives) > 0:

    print(
        false_positives[
            ["url", "domain", "source"]
        ].head(15).to_string(index=False)
    )

else:

    print("No false positives found.")


print("\n========== FALSE NEGATIVE SAMPLES ==========")

if len(false_negatives) > 0:

    print(
        false_negatives[
            ["url", "domain", "source"]
        ].head(15).to_string(index=False)
    )

else:

    print("No false negatives found.")


# ==========================================
# 6. RANDOM FOREST FEATURE IMPORTANCE
# ==========================================

print("\n========== FEATURE IMPORTANCE ==========")

if hasattr(model, "feature_importances_"):

    feature_names = saved_data["feature_names"]

    importance_df = pd.DataFrame({
        "feature": feature_names,
        "importance": model.feature_importances_
    })

    importance_df = importance_df.sort_values(
        by="importance",
        ascending=False
    )

    print(importance_df.to_string(index=False))

    importance_df.to_csv(
        os.path.join(
            OUTPUT_DIR,
            "feature_importance.csv"
        ),
        index=False
    )

else:

    print("Feature importance is not available for this model.")


# ==========================================
# 7. FEATURE ANALYSIS OF WRONG PREDICTIONS
# ==========================================

print("\nAnalyzing features of incorrect predictions...")

feature_rows = []

for _, row in errors.iterrows():

    try:

        features = extract_features(row["url"])

        if not isinstance(features, dict):
            continue

        features["actual_label"] = row["actual_label"]

        features["predicted_label"] = row["predicted_label"]

        features["source"] = row["source"]

        features["url"] = row["url"]

        feature_rows.append(features)

    except Exception as error:

        print("Could not analyze:", row["url"])
        print("Reason:", error)


if feature_rows:

    error_features = pd.DataFrame(feature_rows)

    error_features.to_csv(
        os.path.join(
            OUTPUT_DIR,
            "error_feature_analysis.csv"
        ),
        index=False
    )

    numeric_columns = error_features.select_dtypes(
        include="number"
    ).columns.tolist()

    numeric_columns = [
        column for column in numeric_columns
        if column not in [
            "actual_label",
            "predicted_label"
        ]
    ]

    print("\n========== ERROR FEATURE AVERAGES ==========")

    print(
        error_features.groupby(
            ["source", "actual_label", "predicted_label"]
        )[numeric_columns].mean().round(3).to_string()
    )

else:

    print("No error features available.")


# ==========================================
# 8. FINAL MESSAGE
# ==========================================

print("\nError analysis completed successfully!")

print("Reports saved inside:", OUTPUT_DIR)

print("\nGenerated files:")

print("1. all_errors.csv")

print("2. false_positives.csv")

print("3. false_negatives.csv")

print("4. feature_importance.csv")

print("5. error_feature_analysis.csv")
