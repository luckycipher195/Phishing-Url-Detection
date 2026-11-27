
import pandas as pd
import re

# Load original dataset
df = pd.read_csv("dataset/url_features_extracted1.csv")


# Method 1: Count alphanumeric tokens
def method_1(url):
    return len(re.findall(r"[a-zA-Z0-9]+", str(url)))


# Method 2: Split URL using slash
def method_2(url):
    return len(str(url).split("/"))


# Method 3: Split using common URL separators
def method_3(url):
    tokens = re.split(r"[./?&=_-]+", str(url))
    return len([token for token in tokens if token])


# Store methods
methods = {
    "alphanumeric_tokens": method_1,
    "slash_split": method_2,
    "url_separator_split": method_3
}


# Select 100 random rows
sample = df.sample(100, random_state=42)


# Compare all three methods
print("===== TOKEN COUNT COMPARISON =====")

for name, function in methods.items():

    matches = 0

    for _, row in sample.iterrows():

        calculated = function(row["URL"])
        original = row["token_count"]

        if calculated == original:
            matches += 1

    print(f"{name}: {matches}/100 matches")


# Display mismatch examples from Method 1
print("\n===== MISMATCH EXAMPLES =====")

shown = 0

for _, row in sample.iterrows():

    url = str(row["URL"])
    original = row["token_count"]
    calculated = method_1(url)

    if calculated != original:

        print("\nURL:", url)
        print("Dataset token_count:", original)
        print("Our token_count:", calculated)
        print("Our tokens:", re.findall(r"[a-zA-Z0-9]+", url))

        shown += 1

        if shown == 10:
            break


print("\n===== EXPERIMENT COMPLETED =====")
