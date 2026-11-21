# Advanced Phishing URL Detection System

## Project Overview

The Advanced Phishing URL Detection System is a Python-based cybersecurity project designed to identify potentially malicious URLs using URL analysis, feature extraction, and machine learning techniques.

The system analyses different characteristics of URLs to identify suspicious patterns and aims to classify URLs as phishing or legitimate.

## Objectives

- Analyse URL characteristics and identify suspicious patterns.
- Detect potential phishing URLs using rule-based techniques.
- Extract relevant features from URLs for machine learning.
- Train a machine learning model to classify phishing and legitimate URLs.
- Display detection results with understandable risk explanations.

## Technologies Used

- **Python** – Core programming language.
- **Pandas** – Dataset processing and manipulation.
- **Scikit-learn** – Planned machine learning implementation.
- **Flask** – Planned web application interface.
- **Git and GitHub** – Version control and project management.

## Features Implemented

- URL parsing and validation.
- Detection of suspicious URL patterns.
- Detection of IP-based hostnames.
- Identification of potential brand impersonation.
- URL feature extraction.
- Phishing dataset preparation and cleaning.

## Dataset

The project currently uses a verified phishing URL dataset obtained from PhishTank.

- Original phishing records: 43,127
- Processed phishing records: 43,125
- Extracted features: 7
- Missing values after processing: 0

The dataset is stored locally and excluded from the GitHub repository.

## Project Structure

```text
Phishing-Url-Detection/
│
├── url_checker.py
├── feature_extractor.py
├── prepare_dataset.py
├── dataset/
├── .gitignore
└── README.md
```

## How to Run

1. Clone the repository.
2. Create and activate a Python virtual environment.
3. Install the required dependencies.
4. Run the URL checker:

```bash
python url_checker.py
```

5. To extract URL features independently:

```bash
python feature_extractor.py
```

6. To prepare the phishing dataset:

```bash
python prepare_dataset.py
```

**Note:** Dataset preparation requires the local file `dataset/verified_online.csv`.

## Future Development

- Collect and process legitimate URL datasets.
- Combine phishing and legitimate URL datasets.
- Implement machine learning classification algorithms.
- Evaluate model performance using appropriate metrics.
- Develop a Flask-based web interface.
- Improve detection accuracy and provide risk explanations.

## Project Status

Currently under development.