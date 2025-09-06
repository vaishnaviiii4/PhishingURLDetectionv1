from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
import os
import socket

app = Flask(__name__)
CORS(app)

# Global variables
model = None
scaler = None

def extract_enhanced_features(url):
    """
    Enhanced feature extraction for phishing URL detection.
    This includes more sophisticated features commonly used in phishing detection.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        scheme = parsed_url.scheme
        fragment = parsed_url.fragment
    except Exception:
        # Return neutral features if parsing fails
        return [0] * 25
    
    features = []
    
    # 1. URL Length (normalized)
    features.append(min(len(url) / 100.0, 2.0))  # Cap at 200 chars
    
    # 2. Domain Length (normalized)
    features.append(min(len(domain) / 50.0, 2.0) if domain else 0)  # Cap at 100 chars
    
    # 3. Path Length (normalized)
    features.append(min(len(path) / 50.0, 2.0))  # Cap at 100 chars
    
    # 4. Number of subdomains
    subdomain_count = len(domain.split('.')) - 2 if domain else 0
    features.append(min(max(0, subdomain_count) / 3.0, 2.0))  # Normalize
    
    # 5. Has suspicious TLD
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download']
    features.append(1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0)
    
    # 6. HTTPS usage
    features.append(1 if scheme == 'https' else 0)
    
    # 7. IP address instead of domain
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features.append(1 if re.match(ip_pattern, domain.replace('www.', '')) else 0)
    
    # 8. Port number in URL
    features.append(1 if ':' in domain and not domain.startswith('www.') else 0)
    
    # 9. Shortening service
    shortening_services = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'short.link', 'ow.ly', 'is.gd']
    features.append(1 if any(service in domain.lower() for service in shortening_services) else 0)
    
    # 10. Suspicious keywords in domain
    phishing_keywords = [
        'secure', 'account', 'update', 'confirm', 'login', 'signin', 'bank', 'paypal',
        'amazon', 'microsoft', 'apple', 'google', 'facebook', 'security', 'suspend',
        'verify', 'validation', 'authentication'
    ]
    keyword_count = sum(1 for keyword in phishing_keywords if keyword in domain.lower())
    features.append(min(keyword_count / 3.0, 2.0))  # Normalize
    
    # 11. Number of hyphens in domain
    features.append(min(domain.count('-') / 5.0, 2.0) if domain else 0)
    
    # 12. Number of digits in domain
    digit_count = sum(c.isdigit() for c in domain) if domain else 0
    features.append(min(digit_count / 10.0, 2.0))
    
    # 13. Special characters ratio in URL
    special_chars = '!@#$%^&*()+=[]{}|;:,<>?~`'
    special_count = sum(url.count(char) for char in special_chars)
    features.append(min(special_count / len(url), 1.0) if len(url) > 0 else 0)
    
    # 14. Query parameters count
    param_count = len(query.split('&')) if query else 0
    features.append(min(param_count / 10.0, 2.0))
    
    # 15. Double slashes in path
    features.append(1 if '//' in path else 0)
    
    # 16. URL depth (number of slashes in path)
    path_depth = path.count('/') if path else 0
    features.append(min(path_depth / 5.0, 2.0))
    
    # 17. Has fragment
    features.append(1 if fragment else 0)
    
    # 18. Domain has numbers
    features.append(1 if any(c.isdigit() for c in domain) else 0)
    
    # 19. Long domain name
    features.append(1 if len(domain) > 20 else 0)
    
    # 20. Suspicious file extensions in path
    suspicious_extensions = ['.exe', '.zip', '.rar', '.scr', '.bat', '.com', '.pif']
    features.append(1 if any(ext in path.lower() for ext in suspicious_extensions) else 0)
    
    # 21. Homograph attack detection (basic)
    unicode_suspicious = any(ord(c) > 127 for c in domain)
    features.append(1 if unicode_suspicious else 0)
    
    # 22. Brand impersonation (basic check)
    major_brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'instagram']
    brand_in_subdomain = any(brand in domain.lower().split('.')[0] for brand in major_brands if '.' in domain)
    features.append(1 if brand_in_subdomain and not any(domain.endswith(brand + '.com') for brand in major_brands) else 0)
    
    # 23. Vowel to consonant ratio (unusual ratios might indicate random domains)
    if domain:
        vowels = sum(1 for c in domain.lower() if c in 'aeiou')
        total_letters = sum(1 for c in domain if c.isalpha())
        vowel_ratio = vowels / total_letters if total_letters > 0 else 0
        # Normal ratio is around 0.4, very high or very low might be suspicious
        features.append(abs(vowel_ratio - 0.4) if total_letters > 5 else 0)
    else:
        features.append(0)
    
    # 24. Domain age simulation (in real app, you'd use WHOIS data)
    # For demo, we'll use a heuristic based on domain characteristics
    looks_new = (
        len(domain) > 25 or 
        domain.count('-') > 2 or 
        any(char.isdigit() for char in domain[:5]) or
        any(keyword in domain.lower() for keyword in ['temp', 'test', '2023', '2024', '2025'])
    )
    features.append(1 if looks_new else 0)
    
    # 25. Overall suspiciousness score
    suspicious_indicators = [
        len(url) > 100,
        domain.count('.') > 3,
        domain.count('-') > 1,
        scheme != 'https',
        any(keyword in url.lower() for keyword in phishing_keywords[:5])
    ]
    suspicion_score = sum(suspicious_indicators) / len(suspicious_indicators)
    features.append(suspicion_score)
    
    return features

def create_smart_model():
    """
    Create a more sophisticated model with better feature weights for phishing detection.
    """
    # Create synthetic training data with realistic patterns
    np.random.seed(42)
    n_samples = 2000
    n_features = 25
    
    # Generate features
    X = np.random.rand(n_samples, n_features)
    
    # Create labels based on realistic patterns
    y = np.zeros(n_samples)
    
    for i in range(n_samples):
        # Phishing indicators
        phishing_score = (
            X[i, 0] * 0.3 +  # URL length
            X[i, 4] * 0.2 +  # Suspicious TLD
            (1 - X[i, 5]) * 0.2 +  # No HTTPS
            X[i, 6] * 0.3 +  # IP address
            X[i, 9] * 0.4 +  # Suspicious keywords
            X[i, 10] * 0.2 + # Hyphens
            X[i, 12] * 0.2 + # Special chars
            X[i, 21] * 0.3 + # Brand impersonation
            X[i, 24] * 0.3   # Overall suspicion
        )
        
        # Add some randomness
        phishing_score += np.random.normal(0, 0.1)
        
        # Threshold for classification
        y[i] = 1 if phishing_score > 1.0 else 0
    
    # Train model
    model = LogisticRegression(random_state=42, class_weight='balanced')
    model.fit(X, y)
    
    # Create and fit scaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Retrain with scaled features
    model.fit(X_scaled, y)
    
    return model, scaler

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Extract features
        features = extract_enhanced_features(url)
        
        # Convert to numpy array and reshape
        features_array = np.array(features).reshape(1, -1)
        
        # Scale features
        global model, scaler
        if model is None or scaler is None:
            model, scaler = create_smart_model()
        
        features_scaled = scaler.transform(features_array)
        
        # Make prediction
        prediction = model.predict(features_scaled)[0]
        probabilities = model.predict_proba(features_scaled)[0]
        
        # Calculate confidence
        confidence = max(probabilities)
        
        # Determine result
        is_phishing = bool(prediction)
        
        # Additional context based on features
        risk_factors = []
        if features[0] > 1.5:  # Long URL
            risk_factors.append("Unusually long URL")
        if features[4] == 1:  # Suspicious TLD
            risk_factors.append("Suspicious domain extension")
        if features[5] == 0:  # No HTTPS
            risk_factors.append("No secure connection (HTTPS)")
        if features[6] == 1:  # IP address
            risk_factors.append("Uses IP address instead of domain name")
        if features[9] > 0.5:  # Suspicious keywords
            risk_factors.append("Contains suspicious keywords")
        if features[21] == 1:  # Brand impersonation
            risk_factors.append("Possible brand impersonation")
        
        return jsonify({
            'url': url,
            'is_phishing': is_phishing,
            'confidence': float(confidence),
            'prediction': int(prediction),
            'probabilities': {
                'safe': float(probabilities[0]),
                'phishing': float(probabilities[1])
            },
            'risk_factors': risk_factors,
            'recommendation': 'AVOID - This URL shows signs of being malicious' if is_phishing 
                           else 'PROCEED WITH CAUTION - This URL appears to be safe' if confidence < 0.8 
                           else 'SAFE - This URL appears to be legitimate'
        })
        
    except Exception as e:
        return jsonify({'error': f'Error processing request: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'message': 'Enhanced Phishing Detection API is running'})

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'message': 'Enhanced Phishing URL Detection API',
        'version': '2.0',
        'features': '25 advanced features for better detection accuracy',
        'endpoints': {
            'predict': 'POST /predict - Analyze a URL for phishing',
            'health': 'GET /health - Check API health'
        }
    })

if __name__ == '__main__':
    print("Starting Enhanced Phishing URL Detection API...")
    print("Initializing advanced model with 25 features...")
    model, scaler = create_smart_model()
    print("Enhanced model loaded successfully!")
    print("API available at http://localhost:5001")
    print("Features include: URL analysis, domain inspection, brand impersonation detection, and more")
    app.run(debug=True, host='0.0.0.0', port=5001)
