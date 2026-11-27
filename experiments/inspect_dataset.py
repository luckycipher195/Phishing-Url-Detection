
import pandas as pd

# Step 1: Load the cleaned dataset
file_path = "dataset/cleaned_dataset.csv"

print("Loading cleaned dataset...")
df = pd.read_csv(file_path)

print("\n========== DATASET OVERVIEW ==========")
print("Total records:", len(df))
print("Total columns:", len(df.columns))


# Step 2: Check missing values
print("\n========== MISSING VALUES ==========")
print(df.isnull().sum())


# Step 3: Check data types
print("\n========== DATA TYPES ==========")
print(df.dtypes)


# Step 4: Check feature statistics
feature_columns = [
    column for column in df.columns
    if column not in ["URL", "ClassLabel"]
]

print("\n========== FEATURE STATISTICS ==========")
print(df[feature_columns].describe().T)


# Step 5: Identify constant features
constant_features = [
    column for column in feature_columns
    if df[column].nunique() <= 1
]

print("\n========== CONSTANT FEATURES ==========")

if constant_features:
    print("Features with only one unique value:")
    print(constant_features)
else:
    print("No constant features found.")


# Step 6: Check class distribution
print("\n========== CLASS DISTRIBUTION ==========")
print(df["ClassLabel"].value_counts())

print("\n========== INSPECTION COMPLETED ==========")
