# 🛡️ PhishGuard – Advanced Phishing URL Detection System

**A Hybrid Machine Learning and Rule-Based System for Detecting Suspicious and Phishing URLs.**

PhishGuard is a Python-based cybersecurity project that analyses website URLs using Machine Learning, URL feature extraction, and rule-based detection techniques.

It also maintains a permanent scan history using SQLite, allowing the system to recognise previously scanned URLs.

## 🚀 Key Features

- **Machine Learning Detection:** Uses a trained Random Forest classification model.
- **URL Feature Extraction:** Extracts 16 characteristics from submitted URLs.
- **Rule-Based Detection:** Identifies suspicious URL patterns and possible brand impersonation.
- **Hybrid Risk Assessment:** Combines ML predictions with rule-based indicators.
- **Interactive Dashboard:** Provides a web-based interface using Streamlit.
- **Permanent Scan History:** Stores scan records in an SQLite database.
- **Repeat URL Detection:** Identifies previously scanned URLs.
- **Scan Tracking:** Maintains first-seen time, last-seen time, and scan count.
- **Feature Visualisation:** Displays extracted URL features through tables and charts.

## 🧠 System Architecture

```text
             User Input
                 |
                 v
             URL Scanner
                 |
          Feature Extraction
                 |
          +------+------+
          |             |
          v             v
     Machine Learning  Rule-Based
          Model        Detection
          |             |
          +------+------+
                 |
                 v
          Risk Assessment
                 |
                 v
          Streamlit Dashboard
                 |
                 v
          SQLite Database
                 |
                 v
         Permanent Scan History
```

## 🤖 Machine Learning Model

The project uses a Random Forest classifier trained on URL-based features.

### Dataset

- Source: Mendeley LegitPhish Dataset
- Total records: 100,872
- Extracted features: 16
- Training and testing: Group-based 80:20 split
- Validation strategy: Stratified Group K-Fold

### Model Performance

| Metric | Result |
|---|---:|
| Accuracy | 99.77% |
| Precision (Phishing) | 99.65% |
| Recall (Phishing) | 99.99% |
| F1-Score (Phishing) | 99.82% |

*These results represent the internal held-out test set. They should not be interpreted as guaranteed real-world detection performance.*

## 🗄️ Permanent Threat History

PhishGuard uses SQLite to maintain persistent URL scan records.

For previously scanned URLs, the system can display:

- First detected timestamp
- Last scanned timestamp
- Number of scans
- Previous prediction and risk level

The database updates an existing URL record instead of creating a duplicate record for the same normalised URL.

## 🛠️ Technology Stack

- Python
- Pandas
- NumPy
- Scikit-learn
- Joblib
- TLDExtract
- SQLite
- Streamlit

## 📂 Project Structure

```text
Phishing-Url-Detection/
│
├── app.py
├── url_checker.py
├── database.py
├── feature_extractor_v2.py
├── train_model.py
│
├── requirements.txt
├── README.md
├── .gitignore
│
├── model/
│   └── phishing_model.joblib
│
├── dataset/
│   └── cleaned_dataset.csv
│
└── phishguard.db
```

*Dataset and database files may be generated or downloaded locally and may not be included in the GitHub repository.*

## ⚙️ Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/luckycipher195/Phishing-Url-Detection.git
```

### 2. Navigate to the Project Directory

```bash
cd Phishing-Url-Detection
```

### 3. Create a Virtual Environment

```bash
python -m venv .venv
```

### 4. Install Dependencies

```bash
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 5. Run the Application

```bash
.venv\Scripts\python.exe -m streamlit run app.py
```

The PhishGuard dashboard will open in your browser.

## 🧪 Example Scenarios

| Input | Expected System Behaviour |
|---|---|
| `https://www.google.com` | Analyses the URL and displays the prediction |
| Previously scanned URL | Displays a previously recorded URL alert |
| Suspicious URL | Displays applicable ML and rule-based warnings |

*Actual predictions depend on the trained model and detection rules.*

## 🔐 Security Notice

PhishGuard is an educational cybersecurity project.

- A LOW RISK result does not guarantee that a website is safe.
- ML predictions are not definitive security verdicts.
- Rule-based detection may produce false positives.
- The project does not visit submitted URLs.
- Scan history is stored locally in SQLite.

## 🔮 Future Improvements

- Integration with live threat intelligence feeds.
- Domain reputation checking.
- Advanced URL similarity detection.
- Improved external dataset evaluation.
- User authentication and role-based access.
- Cloud-based threat database.
- Exportable scan reports.

## 👨‍💻 Author

**Lucky Gavhankar**

B.E. Computer Science and Engineering – Cyber Security

GitHub: [@luckycipher195](https://github.com/luckycipher195)

---

**PhishGuard – Detect. Analyse. Protect.**

*Developed for educational and cybersecurity research purposes.*