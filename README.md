# Advanced Phishing URL Detection System

A Python-based cybersecurity project that detects potentially malicious URLs using a **Hybrid Detection Approach** combining Machine Learning and Rule-Based Analysis.

## Project Overview

Phishing attacks use deceptive URLs to trick users into revealing sensitive information such as passwords, banking details and personal data.

This project aims to identify suspicious URLs by analysing their structural characteristics and applying machine learning techniques along with rule-based security checks.

## Key Features

- URL feature extraction
- IP address detection
- HTTPS analysis
- URL entropy calculation
- Domain and subdomain analysis
- Suspicious keyword detection
- Suspicious file extension detection
- Brand impersonation detection
- Machine Learning-based URL classification
- Rule-Based suspicious pattern detection
- Combined risk assessment (LOW, MEDIUM, HIGH)

## System Architecture

The system follows a hybrid detection workflow:

1. User enters a URL.
2. URL features are extracted.
3. The trained Machine Learning model predicts the URL category.
4. Rule-Based Analysis checks for suspicious patterns and brand impersonation.
5. Both results are combined.
6. The system displays the final risk assessment.

## Machine Learning Models

The following models were evaluated:

- Decision Tree
- Random Forest
- Logistic Regression

**Selected Model: Random Forest**

The model was selected based on its performance during the domain-based train-test evaluation.

### Dataset

- Source: Mendeley LegitPhish Dataset
