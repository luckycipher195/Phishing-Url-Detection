
import pandas as pd
from urllib.parse import urlparse
import re

df = pd.read_csv("dataset/url_features_extracted1.csv")

def analyse_url(url):
    url = str(url).strip()

    parsed = urlparse(url)

    if not parsed.hostname:
        parsed = urlparse("//" + url)

    hostname = parsed.hostname or ""

    return {
        "scheme": parsed.scheme,
        "hostname": hostname,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "scheme_tokens": len(re.findall(r"[a-zA-Z0-9]+", parsed.scheme)),
        "hostname_tokens": len(re.findall(r"[a-zA-Z0-9]+", hostname)),
        "path_tokens": len(re.findall(r"[a-zA-Z0-9]+", parsed.path)),
        "query_tokens": len(re.findall(r"[a-zA-Z0-9]+", parsed.query)),
        "fragment_tokens": len(re.findall(r"[a-zA-Z0-9]+", parsed.fragment))
    }


sample = df.sample(20, random_state=42)

for _, row in sample.iterrows():

    result = analyse_url(row["URL"])

    print("\nURL:", row["URL"])
    print("Dataset token_count:", row["token_count"])

    for key, value in result.items():
        print(f"{key}: {value}")

print("\n===== COMPONENT ANALYSIS COMPLETED =====")
