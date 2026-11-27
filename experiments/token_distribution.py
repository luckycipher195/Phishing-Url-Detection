
import pandas as pd

df = pd.read_csv("dataset/url_features_extracted1.csv")

print("===== TOKEN COUNT DISTRIBUTION =====")

print(df["token_count"].value_counts().sort_index())

print("\n===== TOKEN COUNT STATISTICS =====")

print(df["token_count"].describe())

print("\n===== SAMPLE URLS BY TOKEN COUNT =====")

for value in sorted(df["token_count"].dropna().unique())[:10]:

    print(f"\n--- Dataset token_count = {value} ---")

    rows = df[df["token_count"] == value].head(3)

    for _, row in rows.iterrows():
        print("URL:", row["URL"])


print("\n===== ANALYSIS COMPLETED =====")
