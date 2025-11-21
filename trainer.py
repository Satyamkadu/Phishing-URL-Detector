import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from urllib.parse import urlparse
import re
import numpy as np

# --- Define Feature List ---
EXPECTED_FEATURES = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'IpAddress', 'HostnameLength',
    'PathLength', 'QueryLength', 'NumSensitiveWords'
]

# --- Feature Extractor (Same as app.py) ---
def extract_features_for_training(url):
    features = {}
    if not urlparse(url).scheme:
        url = "http://" + url
    
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    path = parsed_url.path

    features['NumDots'] = url.count('.')
    features['SubdomainLevel'] = len(hostname.split('.')) - 2
    features['PathLevel'] = len(path.split('/')) - 1
    features['UrlLength'] = len(url)
    features['NumDash'] = url.count('-')
    features['NumDashInHostname'] = hostname.count('-')
    features['AtSymbol'] = 1 if '@' in url else 0
    features['TildeSymbol'] = 1 if '~' in url else 0
    features['NumUnderscore'] = url.count('_')
    features['NumPercent'] = url.count('%')
    features['NumQueryComponents'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
    features['NumAmpersand'] = url.count('&')
    features['NumHash'] = url.count('#')
    features['NumNumericChars'] = sum(c.isdigit() for c in url)
    features['NoHttps'] = 0 if url.startswith('https') else 1
    features['IpAddress'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else 0
    features['HostnameLength'] = len(hostname)
    features['PathLength'] = len(path)
    features['QueryLength'] = len(parsed_url.query)
    
    sensitive_words = ['secure', 'login', 'signin', 'bank', 'account', 'update', 'password', 'verify']
    features['NumSensitiveWords'] = sum(word in url.lower() for word in sensitive_words)
    
    return [features.get(f, 0) for f in EXPECTED_FEATURES]

def train_and_save_model():
    # 1. Load the dataset
    df = pd.read_csv('Phishing_Legitimate_full.csv')
    
    # 2. Prepare X and y
    # Ensure we only use the columns we expect
    X = df[EXPECTED_FEATURES]
    y = df['CLASS_LABEL']
    
    # 3. Train the model
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # 4. Calculate Accuracy
    accuracy = accuracy_score(y_test, model.predict(X_test))
    
    # 5. Save the model
    joblib.dump(model, 'phishing_detector_model.joblib')
    
    return accuracy * 100