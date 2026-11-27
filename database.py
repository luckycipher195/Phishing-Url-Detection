
import sqlite3
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit


# ==========================================
# DATABASE CONFIGURATION
# ==========================================

DATABASE_NAME = "phishguard.db"


# ==========================================
# URL NORMALISATION
# ==========================================

def normalize_url(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parts = urlsplit(url)

    normalized = urlunsplit((
        parts.scheme.lower(),
        parts.netloc.lower(),
        parts.path or "/",
        parts.query,
        parts.fragment
    ))

    return normalized


# ==========================================
# URL HASH GENERATION
# ==========================================

def generate_url_hash(url):

    normalized_url = normalize_url(url)

    return hashlib.sha256(
        normalized_url.encode("utf-8")
    ).hexdigest()


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

def initialize_database():

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            url TEXT NOT NULL,

            url_hash TEXT UNIQUE NOT NULL,

            prediction TEXT NOT NULL,

            phishing_score REAL NOT NULL,

            legitimate_score REAL NOT NULL,

            risk_level TEXT NOT NULL,

            suspicious_indicators TEXT,

            first_seen TEXT NOT NULL,

            last_seen TEXT NOT NULL,

            scan_count INTEGER DEFAULT 1

        )
    """)

    connection.commit()

    connection.close()


# ==========================================
# CHECK EXISTING URL
# ==========================================

def find_existing_scan(url):

    url_hash = generate_url_hash(url)

    connection = sqlite3.connect(DATABASE_NAME)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM scan_history
        WHERE url_hash = ?
    """, (url_hash,))

    result = cursor.fetchone()

    connection.close()

    if result:

        return dict(result)

    return None


# ==========================================
# SAVE OR UPDATE SCAN
# ==========================================

def save_scan(
    url,
    prediction,
    phishing_score,
    legitimate_score,
    risk_level,
    suspicious_indicators
):

    initialize_database()

    normalized_url = normalize_url(url)

    url_hash = generate_url_hash(normalized_url)

    current_time = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    prediction_text = (
        "PHISHING"
        if prediction == 0
        else "LEGITIMATE"
    )

    indicators = " | ".join(suspicious_indicators)

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM scan_history
        WHERE url_hash = ?
    """, (url_hash,))

    existing_record = cursor.fetchone()

    if existing_record:

        cursor.execute("""
            UPDATE scan_history

            SET
                prediction = ?,
                phishing_score = ?,
                legitimate_score = ?,
                risk_level = ?,
                suspicious_indicators = ?,
                last_seen = ?,
                scan_count = scan_count + 1

            WHERE url_hash = ?
        """, (
            prediction_text,
            phishing_score,
            legitimate_score,
            risk_level,
            indicators,
            current_time,
            url_hash
        ))

        status = "EXISTING"

    else:

        cursor.execute("""
            INSERT INTO scan_history (
                url,
                url_hash,
                prediction,
                phishing_score,
                legitimate_score,
                risk_level,
                suspicious_indicators,
                first_seen,
                last_seen,
                scan_count
            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            normalized_url,
            url_hash,
            prediction_text,
            phishing_score,
            legitimate_score,
            risk_level,
            indicators,
            current_time,
            current_time
        ))

        status = "NEW"

    connection.commit()

    connection.close()

    return status


# ==========================================
# GET ALL SCAN RECORDS
# ==========================================

def get_all_scans():

    initialize_database()

    connection = sqlite3.connect(DATABASE_NAME)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM scan_history
        ORDER BY last_seen DESC
    """)

    records = [
        dict(row)
        for row in cursor.fetchall()
    ]

    connection.close()

    return records
