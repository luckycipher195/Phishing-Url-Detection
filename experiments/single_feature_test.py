
import pandas as pd
from sklearn.metrics import accuracy_score

df = pd.read_csv("dataset/cleaned_dataset.csv")
y = df["ClassLabel"]

rules = {
    "https_flag": lambda x: x.astype(int),
    "has_ip_address": lambda x: (x == 0).astype(int),
    "path_length": lambda x: (x == 0).astype(int),
    "number_of_digits": lambda x: (x == 0).astype(int),
    "percentage_numeric_chars": lambda x: (x == 0).astype(int),
    "suspicious_file_extension": lambda x: (x == 0).astype(int)
}

print("\nCORRECTED SINGLE FEATURE CLASSIFICATION")
print("-" * 45)

for feature, rule in rules.items():
    predictions = rule(df[feature])
    accuracy = accuracy_score(y, predictions) * 100
    print(f"{feature}: {accuracy:.2f}%")

print("-" * 45)

