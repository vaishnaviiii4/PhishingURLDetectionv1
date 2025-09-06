from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
import pickle
from sklearn.linear_model import LogisticRegression
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global variable to store the trained model
model = None

def extract_features(url):
    """
    Extract features from URL similar to the Colab notebook approach.
    This is a simplified version - you may need to adjust based on your exact feature set.
    """
    features = {}
    
    # Parse URL
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        scheme = parsed_url.scheme
    except:
        # If URL parsing fails, return default values
        return [0] * 30  # Assuming 30 features, adjust based on your model
    
    # Feature extraction (similar to common phishing detection features)
    features_list = []
    
    # 1. URL Length
    features_list.append(len(url))
    
    # 2. Domain length
    features_list.append(len(domain) if domain else 0)
    
    # 3. Path length
    features_list.append(len(path))
    
    # 4. Query length
    features_list.append(len(query))
    
    # 5. Number of subdomains
    subdomain_count = len(domain.split('.')) - 2 if domain else 0
    features_list.append(max(0, subdomain_count))
    
    # 6. Number of dots in domain
    features_list.append(domain.count('.') if domain else 0)
    
    # 7. Number of hyphens in domain
    features_list.append(domain.count('-') if domain else 0)
    
    # 8. Number of digits in domain
    features_list.append(sum(c.isdigit() for c in domain) if domain else 0)
    
    # 9. HTTPS check
    features_list.append(1 if scheme == 'https' else 0)
    
    # 10. Suspicious keywords in domain
    suspicious_keywords = ['secure', 'account', 'update', 'login', 'verify', 'bank', 'paypal']
    features_list.append(sum(1 for keyword in suspicious_keywords if keyword in domain.lower()) if domain else 0)
    
    # 11. IP address check
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    features_list.append(1 if re.match(ip_pattern, domain) else 0)
    
    # 12. URL shortening service check
    shortening_services = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'short.link']
    features_list.append(1 if any(service in domain.lower() for service in shortening_services) else 0)
    
    # 13. Special characters count in URL
    special_chars = '!@#$%^&*()+=[]{}|;:,<>?'
    features_list.append(sum(url.count(char) for char in special_chars))
    
    # 14. Number of parameters in query
    features_list.append(len(query.split('&')) if query else 0)
    
    # 15. Double slash in path
    features_list.append(1 if '//' in path else 0)
    
    # Add more features to reach expected count (adjust based on your model)
    # For now, adding dummy features to match typical feature counts
    for i in range(15, 30):
        features_list.append(0)
    
    return features_list

def train_model():
    """
    Train a simple logistic regression model.
    In production, you would load your pre-trained model here.
    """
    # This is a placeholder - you should replace this with loading your actual trained model
    # For demo purposes, we'll create a simple model
    
    # Generate some dummy training data (replace with your actual training process)
    np.random.seed(42)
    X_train = np.random.rand(1000, 30)  # 1000 samples, 30 features
    y_train = np.random.randint(0, 2, 1000)  # Random binary labels
    
    model = LogisticRegression(random_state=42)
    model.fit(X_train, y_train)
    
    return model

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Extract features
        features = extract_features(url)
        
        # Convert to numpy array and reshape for prediction
        features_array = np.array(features).reshape(1, -1)
        
        # Make prediction
        global model
        if model is None:
            model = train_model()
        
        prediction = model.predict(features_array)[0]
        probability = model.predict_proba(features_array)[0]
        
        # Get confidence (probability of the predicted class)
        confidence = max(probability)
        
        # Determine if it's phishing (1) or safe (0)
        is_phishing = bool(prediction)
        
        return jsonify({
            'url': url,
            'is_phishing': is_phishing,
            'confidence': float(confidence),
            'prediction': int(prediction),
            'probabilities': {
                'safe': float(probability[0]),
                'phishing': float(probability[1])
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Error processing request: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'message': 'Phishing detection API is running'})

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'message': 'Phishing URL Detection API',
        'endpoints': {
            'predict': 'POST /predict - Analyze a URL for phishing',
            'health': 'GET /health - Check API health'
        }
    })

if __name__ == '__main__':
    print("Starting Phishing URL Detection API...")
    print("Initializing model...")
    model = train_model()
    print("Model loaded successfully!")
    print("API available at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
