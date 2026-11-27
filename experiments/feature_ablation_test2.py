
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

df = pd.read_csv("dataset/cleaned_dataset.csv")

X = df.drop(columns=["URL", "ClassLabel"])
y = df["ClassLabel"]

# Remove potentially biased features
removed_features = [
    "path_length",
    "https_flag",
    "has_ip_address",
    "number_of_digits",
    "percentage_numeric_chars"
]

X = X.drop(columns=removed_features)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

print("Removed features:", removed_features)
print("\nTraining Random Forest...")

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\nRESULTS AFTER FEATURE REMOVAL")
print("--------------------------------")

print(
    "Accuracy:",
    round(accuracy_score(y_test, predictions) * 100, 4),
    "%"
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=["Phishing", "Legitimate"]
    )
)
