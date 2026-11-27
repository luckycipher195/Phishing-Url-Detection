
import pandas as pd
import re

df = pd.read_csv("dataset/url_features_extracted1.csv")

sample = df.sample(1000, random_state=42)


def method_1(url):
    return len(re.findall(r"[a-zA-Z0-9]+", url))


def method_2(url):
    return len(re.findall(r"[a-zA-Z]+|[0-9]+", url))


def method_3(url):
    return len(re.findall(r"\w+", url))


def method_4(url):
    return len(re.findall(r"[a-zA-Z0-9]+|[^a-zA-Z0-9\s]", url))


def method_5(url):
    return len([x for x in re.split(r"[\W_]+", url) if x])


methods = {
    "alphanumeric_groups": method_1,
    "letters_and_numbers_separate": method_2,
    "word_characters": method_3,
    "words_and_symbols": method_4,
    "split_non_word": method_5
}


print("===== TOKEN METHOD COMPARISON =====")

for name, function in methods.items():

    matches = 0

    for _, row in sample.iterrows():

        url = str(row["URL"])
        original = int(row["token_count"])

        calculated = function(url)

        if calculated == original:
            matches += 1

    print(f"{name}: {matches}/1000 matches")


print("\n===== BEST METHOD MISMATCH EXAMPLES =====")

best_method = method_1
shown = 0

for _, row in sample.iterrows():

    url = str(row["URL"])
    original = int(row["token_count"])
    calculated = best_method(url)

    if calculated != original:

        print("\nURL:", url)
        print("Dataset count:", original)
        print("Calculated count:", calculated)

        shown += 1

        if shown == 10:
            break


print("\n===== EXPERIMENT COMPLETED =====")
