
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Load dataset
df = pd.read_csv("dataset/cleaned_dataset.csv")

X = df.drop(columns=["URL", "ClassLabel"])
y = df["ClassLabel"]

# Remove path_length
X = X.drop(columns=["path_length"])

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# Train Random Forest
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

print("Training Random Forest without path_length...")

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\nRESULTS WITHOUT path_length")
print("----------------------------")

print(
    "Accuracy:",
    round(accuracy_score(y_test, predictions) * 100, 2),
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
