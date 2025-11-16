# URL-Phishing-Detection


## Overview
This project was completed as part of the **Cybersecurity module final project** for the Master's in Data Analytics and Artificial Intelligence. Its goal is to detect phishing URLs and distinguish them from legitimate ones using machine learning models.

## Project Structure
The project is divided into two main Python notebooks in Google Colaboratory:

1. **URL Feature Extraction**
    - Extracts various features from URLs to help classify them as phishing or legitimate.
    - **Address bar features**: domain of URL, presence of IP, '@' symbol, URL length, URL depth, redirection, double slashes, HTTP/HTTPS in domain, URL shortening services, tiny URLs, prefix/suffix in domain.
    - **Domain-based features**: DNS record, web traffic, domain age, and domain registration period.
    - **HTML & JavaScript-based features**: iframe redirection, status bar customization, disabling right-click, and website forwarding.

2. **Phishing URL Detection**
    - Combines the extracted features from 5,000 legitimate URLs and 5,000 phishing URLs into a single dataset.
    - Trains multiple machine learning models on the dataset:
        - Random Forest
        - Decision Tree
        - Support Vector Machine (SVM)
        - XGBoost

## Results
- **XGBoost**: Train & Test Accuracy = 0.7905 
- **Random Forest**: 0.789875
- **SVM**: 0.78875 

The XGBoost model was found to be one of the most effective in detecting phishing URLs.

## Tools & Libraries
- Python, Google Colaboratory
- Scikit-learn, XGBoost
- Pandas, NumPy




