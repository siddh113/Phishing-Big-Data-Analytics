import streamlit as st
import pandas as pd
import joblib
import re
from urllib.parse import urlparse
import whois
import ssl
import socket
from datetime import datetime
import os

model = joblib.load('phishing_rf_model2.pkl')
history_file = 'history.csv'

def check_brand_mismatch(url, real_domain):
    brands = ['google', 'facebook', 'amazon', 'skype', 'microsoft', 'paypal', 'apple', 'youtube', 'linkedin', 'instagram']
    for brand in brands:
        if brand in url.lower() and brand not in real_domain.lower():
            return -1
    return 1

def check_protocol(url):
    return -1 if url.startswith('http://') else 1

def check_suspicious_subdomain(domain):
    subdomain = domain.split('.')[0]
    return -1 if any(char.isdigit() for char in subdomain) and len(subdomain) > 6 else 1

def extract_features(url):
    features = {}
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
    except:
        w = None
        domain = urlparse(url).netloc

    features['having_IPhaving_IP_Address'] = -1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}", url) else 1
    features['URLURL_Length'] = 1 if len(url) < 54 else 0 if len(url) <= 75 else -1
    features['Shortining_Service'] = -1 if re.search(r"bit\.ly|goo\.gl|shorte\.st|tinyurl|t\.co|is\.gd|cli\.gs|wp\.me|buff\.ly|ow\.ly", url) else 1
    features['having_At_Symbol'] = -1 if "@" in url else 1
    features['double_slash_redirecting'] = -1 if url.count('//') > 1 else 1
    features['Prefix_Suffix'] = -1 if '-' in domain else 1
    features['having_Sub_Domain'] = -1 if domain.count('.') > 1 else 1

    try:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        s.settimeout(5.0)
        s.connect((domain, 443))
        ssl_state = 1
    except:
        ssl_state = 1
    features['SSLfinal_State'] = ssl_state

    try:
        if w and w.expiration_date and w.creation_date:
            exp_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            create_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            registration_length = (exp_date - create_date).days
            features['Domain_registeration_length'] = 1 if registration_length >= 365 else -1
        else:
            features['Domain_registeration_length'] = 0
    except:
        features['Domain_registeration_length'] = 0

    features['DNSRecord'] = 1 if w else 1
    features['Brand_Mismatch'] = check_brand_mismatch(url, domain)
    features['Protocol_Safety'] = check_protocol(url)
    features['Suspicious_Subdomain'] = check_suspicious_subdomain(domain)

    dummy_features = {
        'Favicon': 0, 'port': 0, 'HTTPS_token': 0, 'Request_URL': 0,
        'URL_of_Anchor': 0, 'Links_in_tags': 0, 'SFH': 0, 'Submitting_to_email': 0,
        'Abnormal_URL': 0, 'Redirect': 0, 'on_mouseover': 0, 'RightClick': 0,
        'popUpWidnow': 0, 'Iframe': 0, 'age_of_domain': 0, 'web_traffic': 0,
        'Page_Rank': 0, 'Google_Index': 0, 'Links_pointing_to_page': 0, 'Statistical_report': 0
    }
    features.update(dummy_features)

    return features

def save_to_history(url, result, probability):
    row = {
        'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'URL': url,
        'Prediction': "Phishing" if result == "Phishing" else "Legitimate",
        'Confidence (%)': f"{round(max(probability) * 100, 2)}%"
    }
    if os.path.exists(history_file):
        df = pd.read_csv(history_file)
        df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
    else:
        df = pd.DataFrame([row])
    df.to_csv(history_file, index=False)

st.set_page_config(page_title="Phishing URL Detector", layout="centered")
st.title("🔗 Phishing URL Detection App")
st.sidebar.title("📊 Dashboard")
view = st.sidebar.radio("Choose View", ["Detector", "History Dashboard"])

if view == "Detector":
    st.write("Paste a URL below and detect whether it's phishing or legitimate.")

    user_url = st.text_input("Enter URL here:")

    if st.button("🔍 Detect"):
        if user_url:
            features = extract_features(user_url)
            features_df = pd.DataFrame([features])
            features_df['index'] = 0

            model_features = model.feature_names_in_ if hasattr(model, 'feature_names_in_') else features_df.columns
            features_df = features_df[[col for col in model_features if col in features_df.columns]]

            prediction = model.predict(features_df)[0]
            probability = model.predict_proba(features_df)[0]

            result = "Legitimate" if prediction == 1 and features['Brand_Mismatch'] == 1 and features['Protocol_Safety'] == 1 and features['Suspicious_Subdomain'] == 1 else "Phishing"
            save_to_history(user_url, result, probability)

            if result == "Legitimate":
                st.success("✅ This website is **Legitimate**.")
            else:
                st.error("⚠️ Warning! This website is **Phishing**.")

            if features['Brand_Mismatch'] == -1:
                st.warning("⚠️ **Brand Mismatch detected!**")
            if features['Protocol_Safety'] == -1:
                st.warning("⚠️ **Insecure HTTP detected!**")
            if features['Suspicious_Subdomain'] == -1:
                st.warning("⚠️ **Suspicious Subdomain detected!**")
        else:
            st.warning("⚡ Please enter a URL to check.")

elif view == "History Dashboard":
    st.subheader("📜 Detection History")
    if os.path.exists(history_file):
        history_df = pd.read_csv(history_file)
        st.dataframe(history_df[::-1].reset_index(drop=True), use_container_width=True)
    else:
        st.info("No detection history available.")
