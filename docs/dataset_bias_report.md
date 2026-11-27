# Dataset Bias Investigation Report

## 1. Dataset Overview

- Total cleaned records: 100,872
- Phishing records: 63,492
- Legitimate records: 37,380
- Total features: 16
- Unique registered domains: 62,801

## 2. Dataset Bias Investigation

The dataset showed strong differences between phishing and legitimate URLs.

Key observations:

- 94.47% of phishing URLs used HTTP, while 99.99% of legitimate URLs used HTTPS.
- 77.07% of phishing URLs contained IP addresses, compared with 0% of legitimate URLs.
- 98.82% of legitimate URLs had zero path length.
- Almost all phishing URLs had a non-zero path length.
- Phishing URLs contained more digits and suspicious file extensions.

These patterns indicate possible dataset collection bias. The model may learn characteristics of the dataset sources instead of general phishing behaviour.

## 3. Feature Analysis

The five most important features were:

1. path_length
2. token_count
3. https_flag
4. number_of_digits
5. percentage_numeric_chars

The top five features accounted for approximately 87.3% of total Random Forest feature importance.

## 4. Feature Ablation

Feature ablation experiments showed that the model maintained high accuracy even after removing several highly influential features.

This suggests that other features also contain strong class-separating patterns in the dataset.

## 5. Domain-Based Validation

A GroupShuffleSplit evaluation was performed using registered domains.

- Training records: 79,907
- Testing records: 20,965
- Training domains: 50,240
- Testing domains: 12,561
- Overlapping domains: 0
- Accuracy: 99.84%
- Phishing Precision: 99.91%
- Phishing Recall: 99.84%
- Phishing F1-score: 99.87%

No registered domains were shared between the training and testing sets.

## 6. Conclusion

The model achieved high performance on the current dataset, including domain-based validation. However, strong differences between phishing and legitimate URL characteristics indicate possible dataset bias.

Independent dataset evaluation is required before claiming real-world performance or selecting the final model.