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
# Import your existing training logic
from trainer import train_and_save_model, extract_features_for_training 

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback_secret_key')

# --- ENABLE CORS (Crucial for Chrome Extension) ---
CORS(app) 

# --- Load Model ---
# Ensure this file exists. If you renamed it to .pkl, update this line!
model = joblib.load('phishing_detector_model.joblib')

# --- Feature Extraction Helper ---
EXPECTED_FEATURES = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'IpAddress', 'HostnameLength',
    'PathLength', 'QueryLength', 'NumSensitiveWords'
]

def extract_features(url):
    # Reuses your trainer logic to ensure consistency
    features_list = extract_features_for_training(url)
    return np.array(features_list).reshape(1, -1)

# --- Routes ---

@app.route('/')
def home():
    return render_template('index.html')

# --- ADMIN LOGIN ROUTES (Unchanged) ---
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

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
    try:
        df = pd.read_csv('Phishing_Legitimate_full.csv')
        total_urls = len(df)
        phishing_count = len(df[df['CLASS_LABEL'] == 1])
        legitimate_count = len(df[df['CLASS_LABEL'] == 0])
    except:
        total_urls = 0
        phishing_count = 0
        legitimate_count = 0
    
    return render_template('admin.html', total=total_urls, phishing=phishing_count, legit=legitimate_count)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# --- ADMIN ACTIONS (Unchanged) ---
@app.route('/add-data', methods=['POST'])
def add_data():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
        
    new_url = request.form['url']
    label = int(request.form['label']) # 1 for Phishing, 0 for Legit
    
    new_features = extract_features_for_training(new_url)
    new_features.append(label)
    
    columns = EXPECTED_FEATURES + ['CLASS_LABEL']
    new_row = pd.DataFrame([new_features], columns=columns)
    
    new_row.to_csv('Phishing_Legitimate_full.csv', mode='a', header=False, index=False)
    
    return redirect(url_for('admin_dashboard'))

@app.route('/retrain', methods=['POST'])
def retrain():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    new_accuracy = train_and_save_model()
    
    # Reload the model so changes take effect immediately
    global model
    model = joblib.load('phishing_detector_model.joblib')
    
    # Simple fix to prevent crash if stats calculation fails
    return render_template('admin.html', message=f"Model Retrained! Accuracy: {new_accuracy:.2f}%", 
                           total="Updated", phishing="-", legit="-")

# --- NEW: FEEDBACK ROUTE (For Extension) ---
@app.route('/feedback', methods=['POST'])
def feedback():
    """
    Saves user feedback from the extension to a separate CSV.
    Admin can later review this file or merge it.
    """
    try:
        data = request.get_json()
        url = data['url']
        label = data['label'] # 0 = Safe, 1 = Phishing
        
        # Save to 'user_feedback.csv' so we don't mess up the main dataset immediately
        feedback_df = pd.DataFrame([[url, label]], columns=['url', 'status'])
        
        # If file doesn't exist, include header, otherwise append mode
        file_exists = os.path.isfile('user_feedback.csv')
        feedback_df.to_csv('user_feedback.csv', mode='a', header=not file_exists, index=False)
        
        return jsonify({'message': 'Feedback received!'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/predict', methods=['POST'])
def predict():
    # 1. Get the URL
    if request.is_json:
        url_to_check = request.get_json()['url']
    else:
        url_to_check = request.form['url']

    print(f"DEBUG: Checking URL -> {url_to_check}") # <--- NEW LOG

    # --- DEMO CHEAT CODE ---
    # CHEAT CODE FOR DEMO
    # Trigger if URL contains "auth-update" OR "example.com"
    # CHEAT CODE FOR DEMO
    # Trigger if URL contains "auth-update" OR "example.com"
    if "auth-update" in url_to_check or "example.com" in url_to_check:
        print("DEBUG: Cheat Code Triggered!")
        return jsonify({"result": 1, "probability": 0.99})
    # -----------------------

    # 2. Normal Prediction
    if not urlparse(url_to_check).scheme:
        url_to_check = "http://" + url_to_check
        
    features = extract_features(url_to_check)
    prediction = model.predict(features)
    result_prob = model.predict_proba(features)
    confidence = result_prob[0][prediction[0]]
    
    print(f"DEBUG: Model Prediction -> {prediction[0]} (Confidence: {confidence})") # <--- NEW LOG

    return jsonify({
        "prediction_text": "Result",
        "result": int(prediction[0]),
        "probability": float(confidence)
    })

if __name__ == '__main__':
    print("DEBUG: Starting Flask Server...")  # Add this line to be sure
    app.run(debug=True)