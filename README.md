# URL-Phishing-Detection


## Overview
This project was completed as part of the **Cybersecurity module final project** for the Master's in Data Analytics and Artificial Intelligence. Its goal is to detect phishing URLs and distinguish them from legitimate ones using machine learning models.

## ✨ Features

- **Automatic feature extraction** from URLs:
  - URL length, “@” symbol, redirections, shortening services
  - Subdomain depth, IP address presence
  - Digit/special-character ratios
  - Domain age & suspicious patterns
- **Machine Learning Models:**
  - Random Forest
  - XGBoost
  - Support Vector Machine (SVM)
- **Evaluation visuals:**
  - Confusion matrices (3 models)
  - ROC curves
  - Accuracy & F1-score comparison plot
- **Streamlit web interface** for real-time URL prediction


## Model Evaluation Results

| Model          | Accuracy | Precision (Legit / Phish) | Recall (Legit / Phish) | F1-score (Legit / Phish) |
|----------------|---------|---------------------------|------------------------|---------------------------|
| Random Forest  | 0.826   | 0.86 / 0.80               | 0.78 / 0.87            | 0.82 / 0.83               |
| XGBoost        | 0.825   | 0.85 / 0.80               | 0.78 / 0.87            | 0.82 / 0.83               |
| SVM            | 0.819   | 0.85 / 0.79               | 0.77 / 0.86            | 0.81 / 0.83               |


The XGBoost & Random forest models were found to be the most effective in detecting phishing URLs.

## Tools & Libraries
- Python, Google Colaboratory
- Scikit-learn, XGBoost, sklearn.ensebmle.RandomForestClassifier, sklearn.svc 
- Pandas, NumPy, joblic, streamlit, pyngrok



---

## 👤 Project Information

- **Realized by:** Hind Elqorachi, Asma Misbah, Wafa Jaafar, Chayma Belfaik 
- **Supervised by:** [Pr. Monsef Boughrous]  
- **University:** Ibn Zohr University – IT Excellence Center  
- **Module:** Cybersecurity  
- **Program:** Master in Data Analytics & AI  



