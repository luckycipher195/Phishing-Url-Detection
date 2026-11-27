
import pandas as pd

df = pd.read_csv("dataset/cleaned_dataset.csv")

print("\nPATH LENGTH DISTRIBUTION BY CLASS")
print("----------------------------------")

for label, name in [(0, "Phishing"), (1, "Legitimate")]:
    group = df[df["ClassLabel"] == label]

    zero = (group["path_length"] == 0).sum()
    nonzero = (group["path_length"] > 0).sum()

    print(f"\n{name}:")
    print(f"Total URLs: {len(group)}")
    print(f"Zero path length: {zero}")
    print(f"Non-zero path length: {nonzero}")
    print(f"Zero percentage: {zero / len(group) * 100:.2f}%")

print("\nPATH LENGTH SUMMARY")
print(df.groupby("ClassLabel")["path_length"].describe())
