import streamlit as st
import pandas as pd
import numpy as np
import joblib
import requests
from urllib.parse import urlparse
import ipaddress, re

# -------------------------
# Page Config
# -------------------------
st.set_page_config(
    page_title="Phishing URL Detection",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# -------------------------
# Custom CSS
# -------------------------
st.markdown("""
    <style>
        .stApp { background-color: #0D1B2A; color: #FFFFFF; }
        .stButton>button { background-color: #1B263B; color: #FFFFFF; }
        h1, h2, h3, h4, h5 { color: #E0E1DD; text-align:center; }
    </style>
""", unsafe_allow_html=True)

# -------------------------
# Header
# -------------------------
st.title("🔒 Phishing URL Detection System")
st.markdown("<h3>Project: Phishing URL Detection</h3>", unsafe_allow_html=True)
st.markdown("<h3>University: Ibn Zohr – IT Excellence Center</h3>", unsafe_allow_html=True)
st.markdown("<h3>Master: Data Analytics & AI</h3>", unsafe_allow_html=True)
st.markdown("<h3>Module: Cybersecurity</h3>", unsafe_allow_html=True)

# -------------------------
# Load Models and Thresholds
# -------------------------
rf_model = joblib.load("rf_model.pkl")
xgb_model = joblib.load("xgb_model.pkl")
svc_model = joblib.load("svc_model.pkl")

models = {"Random Forest": rf_model, "XGBoost": xgb_model, "SVC": svc_model}
thresholds = {"Random Forest": 0.4, "XGBoost": 0.4, "SVC": 0.5}

# -------------------------
# Manual Override Lists
# -------------------------
trusted_domains = [
    "google.com", "amazon.com", "microsoftonline.com",
    "gmail.com", "outlook.com", "apple.com", "github.com",
    "facebook.com", "youtube.com"
]
shorteners_list = ["bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd", "ow.ly"]
fake_secure_keywords = [
    "secure-", "security-", "verify", "verification", "validate",
    "confirm", "confirmation", "update-info", "update-account",
    "unlock", "recovery", "support-center", "customer-support",
    "login-secure", "account-protect", "identity-check"
]
suspicious_tlds = [
    ".xyz", ".top", ".click", ".info", ".monster", ".online", ".live",
    ".space", ".site", ".loan", ".stream"
]
suspicious_path_keywords = [
    "login", "verify", "update", "signin", "account", "secure",
    "wp-admin", "password", "billing"
]

# -------------------------
# Feature Extraction
# -------------------------
shortening_services = r"(bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bitly)"
feature_columns = [
    'Have_IP','Have_At','URL_Length','URL_Depth','Redirection','HTTPS',
    'Shortener','Prefix_Suffix','Subdomain_Count','Digit_Count','SpecialChar_Count',
    'Sensitive_Keyword','Domain_Age','Domain_Extension','iFrame','MouseOver',
    'RightClick','Forwarding','Form_Tag','Suspicious_JS'
]

def featureExtraction(url):
    features = []
    domain = urlparse(url).netloc.replace("www.", "")
    features.append(domain)

    # Lexical
    try:
        ipaddress.ip_address(domain)
        features.append(1)
    except:
        features.append(0)
    features.append(1 if "@" in url else 0)
    features.append(1 if len(url) >= 54 else 0)
    features.append(len([x for x in urlparse(url).path.split("/") if x]))
    pos = url.rfind("//")
    features.append(1 if pos > 6 else 0)
    features.append(1 if url.startswith("https") else 0)
    features.append(1 if re.search(shortening_services, url) else 0)
    features.append(1 if "-" in domain else 0)
    features.append(len(domain.split("."))-1)
    features.append(sum(c.isdigit() for c in domain))
    features.append(len(re.findall(r"[^a-zA-Z0-9.]", domain)))
    features.append(1 if any(k in url.lower() for k in ["secure","account","update","login","verify","bank","confirm"]) else 0)
    features.append(1 if len(domain)<10 else 0)
    features.append(1 if domain.endswith((".com",".org",".net")) else 0)

    # HTML/JS
    try:
        r = requests.get(url, timeout=3)
        html = r.text
    except:
        html = ""
    features.append(0 if "<iframe" in html else 1)
    features.append(1 if "onmouseover" in html else 0)
    features.append(0 if "event.button" in html else 1)
    features.append(1 if "window.location" in html else 0)
    features.append(1 if "<form" in html else 0)
    features.append(1 if any(f in html for f in ["eval(","escape(","unescape("]) else 0)

    return features

# -------------------------
# URL Input
# -------------------------
url_input = st.text_input("Enter a URL to analyze:")

# -------------------------
# Model Selection
# -------------------------
selected_model_name = st.selectbox("Choose model:", list(models.keys()))
model = models[selected_model_name]
threshold = thresholds[selected_model_name]

# -------------------------
# Prediction
# -------------------------
if st.button("Predict"):
    if not url_input:
        st.warning("Please enter a URL.")
    else:
        domain = urlparse(url_input).netloc.replace("www.","").lower()
        url_lower = url_input.lower()
        tld = "." + domain.split(".")[-1]

        # Apply manual overrides
        override_pred = None
        reasons = []

        if any(td in domain for td in trusted_domains):
            override_pred = "Legitimate"
            reasons.append("Trusted domain")
        if any(s in url_lower for s in shorteners_list):
            override_pred = "Phishing"
            reasons.append("URL shortener detected")
        if any(k in url_lower for k in fake_secure_keywords):
            override_pred = "Phishing"
            reasons.append("Fake 'secure' keywords found")
        if tld in suspicious_tlds:
            override_pred = "Phishing"
            reasons.append("Suspicious TLD")
        if any(p in url_lower for p in suspicious_path_keywords):
            override_pred = "Phishing"
            reasons.append("Suspicious path keywords")
        if "-" in domain:
            reasons.append("Prefix/suffix '-' in domain")
        if sum(c.isdigit() for c in domain) > 3:
            reasons.append("Too many digits in domain")
        if len(domain.split("."))-1 > 3:
            reasons.append("Too many subdomains")

        # Feature extraction
        features = featureExtraction(url_input)
