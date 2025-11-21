import os
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, request, render_template, jsonify, redirect, url_for, session
import joblib
from urllib.parse import urlparse
import numpy as np
import re
from flask_cors import CORS
import pandas as pd
import os
from trainer import train_and_save_model, extract_features_for_training # Import our new script

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback_secret_key')
CORS(app)

# --- Load Model ---
model = joblib.load('phishing_detector_model.joblib')

# --- Feature Extraction (Keep this for the prediction API) ---
EXPECTED_FEATURES = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'IpAddress', 'HostnameLength',
    'PathLength', 'QueryLength', 'NumSensitiveWords'
]

def extract_features(url):
    # ... (Reuse your existing logic here, or just call the one from trainer.py) ...
    # For simplicity, let's reuse the one from trainer.py to avoid code duplication
    features_list = extract_features_for_training(url)
    return np.array(features_list).reshape(1, -1)

# --- Routes ---

@app.route('/')
def home():
    return render_template('index.html')

# --- ADMIN LOGIN ROUTES ---
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Secure check using environment variables
        valid_user = os.getenv('ADMIN_USERNAME')
        valid_pass = os.getenv('ADMIN_PASSWORD')

        if username == valid_user and password == valid_pass:
            session['logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('login.html', error="Invalid Credentials")
    return render_template('login.html')

@app.route('/admin')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    # Get stats from the CSV file
    df = pd.read_csv('Phishing_Legitimate_full.csv')
    total_urls = len(df)
    phishing_count = len(df[df['CLASS_LABEL'] == 1])
    legitimate_count = len(df[df['CLASS_LABEL'] == 0])
    
    return render_template('admin.html', total=total_urls, phishing=phishing_count, legit=legitimate_count)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# --- ADMIN ACTIONS ---
@app.route('/add-data', methods=['POST'])
def add_data():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
        
    new_url = request.form['url']
    label = int(request.form['label']) # 1 for Phishing, 0 for Legit
    
    # 1. Extract features for this new URL
    new_features = extract_features_for_training(new_url)
    new_features.append(label) # Add the label to the end
    
    # 2. Create a DataFrame row
    columns = EXPECTED_FEATURES + ['CLASS_LABEL']
    new_row = pd.DataFrame([new_features], columns=columns)
    
    # 3. Append to CSV
    new_row.to_csv('Phishing_Legitimate_full.csv', mode='a', header=False, index=False)
    
    return redirect(url_for('admin_dashboard'))

@app.route('/retrain', methods=['POST'])
def retrain():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    # Call our trainer script
    new_accuracy = train_and_save_model()
    
    # Reload the model in memory so the app uses the new version immediately
    global model
    model = joblib.load('phishing_detector_model.joblib')
    
    return render_template('admin.html', message=f"Model Retrained! Accuracy: {new_accuracy:.2f}%", 
                           total=0, phishing=0, legit=0) # (Simpler to just show message)

# --- API ---
@app.route('/predict', methods=['POST'])
def predict():
    url_to_check = request.form['url']
    if not urlparse(url_to_check).scheme:
        url_to_check = "http://" + url_to_check
    features = extract_features(url_to_check)
    prediction = model.predict(features)
    result_prob = model.predict_proba(features)
    confidence = result_prob[0][prediction[0]] * 100
    result = "This is a Phishing URL" if prediction[0] == 1 else "This is a Legitimate URL"
    return jsonify({"prediction_text": f"{result} ({confidence:.2f}% confidence)"})

if __name__ == '__main__':
    app.run(debug=True)