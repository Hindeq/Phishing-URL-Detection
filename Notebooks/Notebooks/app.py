
import streamlit as st
import numpy as np
import pickle
from urllib.parse import urlparse,urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests
import os
import pytz # Import pytz for timezone handling

# Define the path to the model
model_path = '/content/drive/MyDrive/url-phishing-detection/CyberSecurity/Model/XGBoostClassifier.pickle.dat'

# Load the pre-trained XGBoost model
try:
    with open(model_path, 'rb') as f:
        xgb_model = pickle.load(f)
except FileNotFoundError:
    st.error("Model file not found. Please check the path.")
    st.stop()

# Feature Extraction Functions (Copied from the notebook)
# 1.Domain of the URL (Domain)
def getDomain(url):
  domain = urlparse(url).netloc
  if re.match(r"^www.",domain):
               domain = domain.replace("www.","")
  return domain

# 2.Checks for IP address in URL (Have_IP)
def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip

# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
  if "@" in url:
    at = 1
  else:
    at = 0
  return at

# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
  if len(url) < 54:
    length = 0
  else:
    length = 1
  return length

# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

# 6.Checking for redirection "//" in the url (Redirection)
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0

#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"                       r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"                       r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"                       r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|"                       r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|"                       r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"                       r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"                       r"tr\.im|link\.zip\.net"

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0

# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0            # legitimate

# 12.Web traffic (Web_Traffic)
def web_traffic(url):
  try:
    #Filling the whitespaces in the URL if any
    url = urllib.parse.quote(url)
    # Attempt to get the rank from Alexa
    try:
        rank_xml = urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read()
        rank = BeautifulSoup(rank_xml, "xml").find("REACH")['RANK']
        rank = int(rank)
    except (urllib.error.URLError, AttributeError) as e:
        # Handle cases where URL cannot be opened or RANK is not found
        # Check specifically for the "Name or service not known" error
        if isinstance(e, urllib.error.URLError) and "[Errno -2] Name or service not known" in str(e):
             return 1 # Return 1 (phishing) for this specific DNS resolution error
        else:
             return 1 # Return 1 (phishing) for other URL errors or AttributeErrors


  except TypeError:
        return 1 # Return 1 (phishing) for other TypeErrors

  if rank <100000:
    return 1
  else:
    return 0

def domainAge(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date

  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 1
  else:
    # Ensure both datetimes are timezone-naive or timezone-aware consistently
    if creation_date.tzinfo is not None and creation_date.tzinfo.utcoffset(creation_date) is not None:
        creation_date = creation_date.replace(tzinfo=None)
    if expiration_date.tzinfo is not None and expiration_date.tzinfo.utcoffset(expiration_date) is not None:
        expiration_date = expiration_date.replace(tzinfo=None)

    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1
    else:
      age = 0
  return age

def domainEnd(domain_name):
  expiration_date = domain_name.expiration_date

  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    # Ensure both datetimes are timezone-naive or timezone-aware consistently
    today = datetime.now()
    if expiration_date.tzinfo is not None and expiration_date.tzinfo.utcoffset(expiration_date) is not None:
        expiration_date = expiration_date.replace(tzinfo=None)
    if today.tzinfo is not None and today.tzinfo.utcoffset(today) is not None:
         today = today.replace(tzinfo=None)


    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  return end

# 15. IFrame Redirection (iFrame)
def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 0
      else:
          return 1

# 16.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
  if response == "" :
    return 1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1
    else:
      return 0

# 17.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1

# 18.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1


#Function to extract features
def featureExtraction(url,label): # Added label back for consistency with original function signature
  features = []
  #Address bar based features (10)
  features.append(getDomain(url))
  features.append(havingIP(url))
  features.append(haveAtSign(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))

  #Domain based features (4)
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
  except:
    dns = 1

  features.append(dns)
  features.append(web_traffic(url))
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))

  # HTML & Javascript based features (4)
  try:
    response = requests.get(url)
  except:
    response = ""
  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))
  features.append(forwarding(response))
  features.append(label) # Include label in the returned features list


  return features


# Streamlit application layout
st.set_page_config(page_title="Phishing URL Detector", layout="centered", initial_sidebar_state="collapsed")

st.title("🚨 Phishing URL Detector")

st.markdown("""
Welcome to the Phishing URL Detector. Enter a URL below to check if it is likely a legitimate or a phishing website.
""")

# Add a selectbox with example URLs
example_urls = {
    "Select an example URL": "",
    "https://www.google.com": "https://www.google.com",
    "https://www.amazon.com": "https://www.amazon.com",
    "https://signin.dropbox.com.access-login.com": "https://signin.dropbox.com.access-login.com", # Example phishing URL structure
    "https://www.paypal.com.secure-account-update.net": "https://www.paypal.com.secure-account-update.net" # Example phishing URL structure
}

# Create a list of keys and values to display in the selectbox
example_options = [f"{label} ({url})" for label, url in example_urls.items()]


selected_example_label_and_url = st.selectbox("Or select an example URL:", example_options)

# Extract the URL from the selected string
selected_example_url = example_urls[selected_example_label_and_url.split(" (")[0]]


# Text input for the URL
url_input = st.text_input("Enter a URL to check:", key="url_input", value=selected_example_url)


# Add a button to trigger the prediction
if st.button("Predict"):
    # Determine the URL to use for prediction
    url_to_predict = url_input if url_input else selected_example_url

    if url_to_predict:
        # Add a spinner while processing
        with st.spinner("Analyzing URL..."):
            # Extract features from the input URL
            # Pass a dummy label (e.g., 1) as it's not used for prediction itself
            features = featureExtraction(url_to_predict, 1)
            # The featureExtraction function returns a list including the domain name as the first element
            # and the label as the last element.
            # The model expects a numpy array of numerical features, so we need to remove the domain name
            # and the label and convert the remaining features to a numpy array.
            # Ensure the numerical features have the correct shape (1, 17) after removing domain and label
            if len(features) == 18: # Check if the original feature list includes the domain and label
                 numerical_features = np.array(features[1:-1]).reshape(1, -1) # Exclude domain and label
            elif len(features) == 17: # If the label was already removed (shouldn't happen with the fix)
                 numerical_features = np.array(features[1:]).reshape(1, -1) # Exclude only domain
            else: # Handle unexpected number of features
                 st.error("Error: Unexpected number of features extracted.")
                 numerical_features = None # Set to None to prevent prediction


        if numerical_features is not None:
            # Make a prediction using the loaded model
            prediction = xgb_model.predict(numerical_features)

            # Display the prediction result
            if prediction[0] == 1:
                st.error("⚠️ This URL is likely PHISHING.")
            else:
                st.success("✅ This URL is likely LEGITIMATE.")
    else:
        st.warning("Please enter a URL or select an example.")

st.markdown("---")
st.markdown("Built for Cybersecurity Course - MASTER's ADIA, University Ibn Zohr - Excellence Center IT, Academic year 2025-2026")

