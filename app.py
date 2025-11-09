from flask import Flask, request, render_template
import joblib
from urllib.parse import urlparse
import numpy as np
import re # Import regular expressions for IP check

# --- Create the Flask App ---
app = Flask(__name__)

# --- Load the NEW, SIMPLER Trained Model ---
# --- Load the NEW, SIMPLER Trained Model ---
model = joblib.load('phishing_detector_model.joblib')

# --- This list defines the features for our NEW model ---
EXPECTED_FEATURES = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'IpAddress', 'HostnameLength',
    'PathLength', 'QueryLength', 'NumSensitiveWords'
]

# --- Feature Extraction Function (Final, Corrected Version) ---
def extract_features(url):
    features = {}
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    path = parsed_url.path

    # --- Calculate features and store them in a dictionary by name ---
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
    
    # --- Build the final list in the correct order ---
    final_features = [features.get(f_name, 0) for f_name in EXPECTED_FEATURES]
    
    return np.array(final_features).reshape(1, -1)

# --- Define Routes ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url_to_check = request.form['url']
    
    # Add http:// if no scheme is present, as urlparse needs it
    if not urlparse(url_to_check).scheme:
        url_to_check = "http://" + url_to_check
        
    features = extract_features(url_to_check)
    prediction = model.predict(features)
    result_prob = model.predict_proba(features)
    
    confidence = result_prob[0][prediction[0]] * 100
    result = "This is a Phishing URL" if prediction[0] == 1 else "This is a Legitimate URL"
    
    return render_template('result.html', prediction_text=f"{result} ({confidence:.2f}% confidence)", url=request.form['url'])

# --- Run the App ---
if __name__ == '__main__':
    app.run(debug=True)