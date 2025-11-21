import pandas as pd
import os

# 1. Define the EXACT columns we want to keep (20 features + label)
EXPECTED_FEATURES = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'IpAddress', 'HostnameLength',
    'PathLength', 'QueryLength', 'NumSensitiveWords', 'CLASS_LABEL'
]

filename = 'Phishing_Legitimate_full.csv'

print(f"Attempting to fix {filename}...")

try:
    # 2. Read the file (skipping bad lines if it's already broken)
    # on_bad_lines='skip' will ignore the broken row you just added
    df = pd.read_csv(filename, on_bad_lines='skip')
    
    # 3. Check if we have the columns we need
    # (We use set intersection to find which columns are actually present)
    existing_columns = [col for col in EXPECTED_FEATURES if col in df.columns]
    
    if len(existing_columns) < len(EXPECTED_FEATURES):
        print("Warning: Some columns were missing from the original file!")
        print(f"Found: {len(existing_columns)} / {len(EXPECTED_FEATURES)}")
    
    # 4. Select ONLY the columns we use
    df_clean = df[existing_columns]
    
    # 5. Save it back, overwriting the old file
    df_clean.to_csv(filename, index=False)
    
    print("Success! The CSV file has been cleaned.")
    print(f"New shape: {df_clean.shape} (Should have 21 columns)")

except Exception as e:
    print(f"Error fixing CSV: {e}")