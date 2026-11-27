
import os
import joblib
import pandas as pd

from feature_extractor_v2 import extract_features

from sklearn.model_selection import train_test_split
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
df = df.dropna(subset=["URL", "ClassLabel"])

print("Total URLs:", len(df))


# STEP 2: Extract features

print("\nExtracting features from URLs...")

feature_records = []

for index, url in enumerate(df["URL"], start=1):

    try:
        feature_records.append(extract_features(url))

    except (ValueError, TypeError):
        feature_records.append(None)

    if index % 10000 == 0:
        print(f"Processed {index}/{len(df)} URLs")


# Remove invalid records

valid_indices = [
    i for i, features in enumerate(feature_records)
    if features is not None
]

X = pd.DataFrame(
    [feature_records[i] for i in valid_indices]
)

y = df.iloc[valid_indices]["ClassLabel"].astype(int)

print("\nValid records:", len(X))
print("Number of features:", X.shape[1])

print("\nFeature names:")
print(X.columns.tolist())


# STEP 3: Split dataset

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining records:", len(X_train))
print("Testing records:", len(X_test))


# STEP 4: Define models

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


# STEP 5: Train and evaluate models

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

    # Classification report
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


# STEP 6: Save model comparison

results_df = pd.DataFrame(results)

print("\n========== MODEL COMPARISON ==========")
print(results_df.to_string(index=False))

results_df.to_csv(
    "model/model_comparison.csv",
    index=False
)

print("\nModel comparison saved.")


# STEP 7: Select best model

best_model_name = results_df.loc[
    results_df["Phishing F1-Score"].idxmax(),
    "Model"
]

best_model = trained_models[best_model_name]

print("\nBest model:", best_model_name)


# STEP 8: Generate best model evaluation

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

# Save confusion matrix

confusion_df = pd.DataFrame(
    best_matrix,
    index=["Actual Phishing", "Actual Legitimate"],
    columns=["Predicted Phishing", "Predicted Legitimate"]
)

confusion_df.to_csv(
    "model/confusion_matrix.csv"
)

# Save classification report

with open(
    "model/classification_report.txt",
    "w",
    encoding="utf-8"
) as file:

    file.write(f"Best Model: {best_model_name}\n\n")
    file.write(best_report)

# Save all model reports

with open(
    "model/all_model_reports.txt",
    "w",
    encoding="utf-8"
) as file:

    for name, report in evaluation_reports.items():

        file.write(f"\n========== {name} ==========\n")
        file.write(report)
        file.write("\n")


# STEP 9: Save trained model

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


# STEP 10: Final output

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

print("\nTraining and evaluation completed successfully!")
