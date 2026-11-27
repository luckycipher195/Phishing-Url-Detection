
import pandas as pd
from sklearn.model_selection import train_test_split
from feature_extractor_v2 import extract_features
from urllib.parse import urlsplit, urlunsplit
from pathlib import Path


DATASET_PATH = Path("dataset/cleaned_dataset.csv")
REPORT_PATH = Path("model/data_quality_report.txt")
DUPLICATES_PATH = Path("model/duplicate_url_groups.csv")


def normalize_url(url):
    """Normalize a URL for duplicate and leakage checks."""

    url = str(url).strip()

    if not url:
        return ""

    if "://" not in url:
        url = "http://" + url

    try:
        parsed = urlsplit(url)

        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            return url.lower()

        port = parsed.port

        if port and not (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        ):
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        return urlunsplit((
            scheme,
            netloc,
            parsed.path or "/",
            parsed.query,
            ""
        ))

    except ValueError:
        return url.lower()


def main():

    print("Loading dataset...")

    df = pd.read_csv(DATASET_PATH)

    required_columns = {"URL", "ClassLabel"}

    if not required_columns.issubset(df.columns):
        raise ValueError(
            "Dataset must contain URL and ClassLabel columns."
        )

    df = df.dropna(subset=["URL", "ClassLabel"]).copy()

    df["normalized_url"] = df["URL"].apply(normalize_url)

    total_rows = len(df)

    # 1. Exact duplicate URLs
    exact_duplicate_rows = int(
        df["URL"].astype(str).str.strip().duplicated(keep=False).sum()
    )

    exact_duplicate_groups = int(
        df["URL"].astype(str).str.strip().value_counts()
        .gt(1).sum()
    )

    # 2. Normalized duplicate URLs
    normalized_counts = df["normalized_url"].value_counts()

    duplicate_groups = normalized_counts[normalized_counts > 1]

    normalized_duplicate_rows = int(
        df["normalized_url"].isin(duplicate_groups.index).sum()
    )

    # 3. Conflicting labels
    label_counts = df.groupby("normalized_url")[
        "ClassLabel"
    ].nunique()

    conflicting_urls = label_counts[label_counts > 1].index

    conflict_count = len(conflicting_urls)

    # 4. Reproduce feature extraction validity filtering
    valid_indices = []

    print("Checking URL feature extraction...")

    for index, url in df["URL"].items():
        try:
            extract_features(url)
            valid_indices.append(index)
        except (ValueError, TypeError):
            pass

    valid_df = df.loc[valid_indices].copy()

    X = valid_df.drop(
        columns=["URL", "ClassLabel", "normalized_url"]
    ) if all(
        column in valid_df.columns
        for column in ["URL", "ClassLabel", "normalized_url"]
    ) else valid_df[["normalized_url"]]

    y = valid_df["ClassLabel"]

    # Same split settings used in model training
    train_indices, test_indices = train_test_split(
        valid_df.index,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    train_urls = set(
        valid_df.loc[train_indices, "normalized_url"]
    )

    test_urls = set(
        valid_df.loc[test_indices, "normalized_url"]
    )

    overlapping_urls = train_urls.intersection(test_urls)

    # Save duplicate groups
    duplicate_report = (
        df[df["normalized_url"].isin(duplicate_groups.index)]
        .groupby("normalized_url")
        .agg(
            occurrences=("URL", "count"),
            distinct_labels=("ClassLabel", "nunique"),
            labels=("ClassLabel", lambda values:
                    ", ".join(map(str, sorted(values.unique())))),
            sample_url=("URL", "first")
        )
        .reset_index()
    )

    duplicate_report.to_csv(DUPLICATES_PATH, index=False)

    # Generate report
    report = f"""
ADVANCED PHISHING URL DETECTION
DATA QUALITY AND DATA LEAKAGE REPORT
====================================

Total dataset rows: {total_rows}

1. EXACT DUPLICATES
-------------------
Rows belonging to exact duplicate groups: {exact_duplicate_rows}
Number of exact duplicate groups: {exact_duplicate_groups}

2. NORMALIZED DUPLICATES
------------------------
Rows belonging to normalized duplicate groups: {normalized_duplicate_rows}
Number of normalized duplicate groups: {len(duplicate_groups)}

3. LABEL CONFLICTS
------------------
URLs with conflicting labels: {conflict_count}

4. FEATURE EXTRACTION
---------------------
Valid URLs: {len(valid_df)}
Invalid URLs: {total_rows - len(valid_df)}

5. TRAIN-TEST LEAKAGE CHECK
---------------------------
Training rows: {len(train_indices)}
Testing rows: {len(test_indices)}
Unique URLs appearing in both sets: {len(overlapping_urls)}

INTERPRETATION
--------------
If URLs appear in both training and testing sets,
the evaluation may be affected by duplicate leakage.

If the same normalized URL has multiple labels,
the dataset may contain inconsistent labeling.

These results require further investigation.
They do not independently prove model performance.
"""

    REPORT_PATH.write_text(report, encoding="utf-8")

    print(report)

    print("Reports saved:")
    print(REPORT_PATH)
    print(DUPLICATES_PATH)


if __name__ == "__main__":
    main()
