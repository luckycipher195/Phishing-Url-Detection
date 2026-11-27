# Advanced Phishing URL Detection System

## Project Overview

The **Advanced Phishing URL Detection System** is a Python-based cybersecurity project that identifies potentially malicious URLs using a combination of rule-based detection and machine learning.

The system analyses URL characteristics, extracts 16 relevant features, and uses a trained machine learning model to classify URLs as **Phishing** or **Legitimate**. It also provides suspicious-pattern warnings to help users understand potential risks.

## Project Objectives

- Identify suspicious URL patterns using rule-based techniques.
- Extract meaningful features from URLs.
- Train and evaluate multiple machine learning algorithms.
- Classify URLs as phishing or legitimate.
- Combine rule-based detection with machine learning predictions.
- Provide understandable detection results and risk indicators.

## Technologies Used

- **Python** – Core programming language.
- **Pandas** – Dataset processing and manipulation.
- **NumPy** – Numerical operations.
- **Scikit-learn** – Machine learning algorithms and evaluation.
- **Joblib** – Saving and loading the trained model.
- **Git and GitHub** – Version control and project management.

## Features Implemented

### 1. URL Validation
- Validates URL input.
- Checks for missing or invalid hostnames.
- Detects invalid port numbers and whitespace in hostnames.

### 2. Rule-Based Detection
- Detects IP-based hostnames.
- Identifies URLs without HTTPS.
- Checks suspicious keywords.
- Detects excessive URL length and hyphens in hostnames.
- Identifies potential brand impersonation.
- Checks suspicious domain patterns.

### 3. Feature Extraction

The system extracts 16 features from each URL:

1. URL Length
2. IP Address Detection
3. Dot Count
4. HTTPS Flag
5. URL Entropy
6. Token Count
7. Subdomain Count
8. Query Parameter Count
9. TLD Length
10. Path Length
11. Hyphen in Domain
12. Number of Digits
13. TLD Popularity
14. Suspicious File Extension
15. Domain Name Length
16. Percentage of Numeric Characters

### 4. Machine Learning Classification

Three machine learning algorithms are trained and evaluated:

- Decision Tree Classifier
- Random Forest Classifier
- Logistic Regression

The Random Forest model was selected based on its phishing F1-score and saved for URL prediction.

### 5. Model Evaluation

The models are evaluated using:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion Matrix
- Classification Report

**Recorded test-set results:**

| Model | Accuracy | Phishing F1-score |
|---|---:|---:|
| Decision Tree | 99.93% | 99.94% |
| Random Forest | 99.94% | 99.95% |
| Logistic Regression | 99.57% | 99.66% |

*Note: These results are from a held-out split of the current dataset. They do not guarantee the same performance on new, real-world URLs.*

## Dataset

The project uses the **LegitPhish dataset**, obtained from Mendeley Data.

- Dataset: 100,872 URL records
- Phishing URLs: 63,492
- Legitimate URLs: 37,380
- Target column: `ClassLabel`
- Label 0: Phishing
- Label 1: Legitimate

The dataset is stored locally in the `dataset/` directory and excluded from the GitHub repository.

Dataset source: https://data.mendeley.com/datasets/hx4m73v2sf/2

## Project Structure

```text
Phishing-Url-Detection/
│
├── docs/
│   └── dataset_bias_report.md
│
├── experiments/
│   └── Experimental scripts and analysis
│
├── model/
│   ├── phishing_model.joblib
│   ├── model_comparison.csv
│   ├── confusion_matrix.csv
│   ├── classification_report.txt
│   └── all_model_reports.txt
│
├── dataset/                 # Local dataset; not uploaded
├── .venv/                   # Python virtual environment
│
├── feature_extractor_v2.py
├── train_model.py
├── url_checker.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/luckycipher195/Phishing-Url-Detection.git
cd Phishing-Url-Detection
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Add the Dataset

Place the required dataset file at:

```text
dataset/cleaned_dataset.csv
```

The dataset is not included in the repository.

## How to Run

### Train the Machine Learning Models

```bash
python train_model.py
```

This trains and evaluates the selected algorithms and saves the model and evaluation reports in the `model/` directory.

### Check a URL

```bash
python url_checker.py
```

Enter a URL when prompted to receive its detection result.

### Extract URL Features

```bash
python feature_extractor_v2.py
```

Enter a URL to view its extracted features.

## Limitations

- Rule-based detection may produce false positives.
- Machine learning predictions depend on the quality and representation of the training dataset.
- High test-set performance does not guarantee real-world detection accuracy.
- Further testing on independent and previously unseen URLs is required.

## Future Development

- Develop a web-based interface.
- Integrate additional threat intelligence sources.
- Improve detection of advanced phishing techniques.
- Perform independent validation using unseen datasets.
- Enhance explainability and risk assessment.

## Project Status

**Core implementation completed; further validation and enhancements are in progress.**
