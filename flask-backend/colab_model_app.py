from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os
from feature_extractor import extract_features_for_colab_model, FEATURE_NAMES

app = Flask(__name__)
CORS(app)

# Global variable to store the trained model
model = None
accuracy = None

def create_synthetic_dataset():
    """
    Create a synthetic dataset that matches your Colab structure.
    In production, you would load your actual dataset here.
    """
    np.random.seed(42)  # For reproducible results
    n_samples = 11054  # Same as your dataset
    n_features = 30
    
    # Generate features with values -1, 0, 1 (matching your dataset)
    X = np.random.choice([-1, 0, 1], size=(n_samples, n_features), p=[0.4, 0.2, 0.4])
    
    # Create more realistic labels based on feature patterns
    # Features that typically indicate phishing when positive
    phishing_indicators = [0, 1, 2, 3, 4, 5, 6, 7, 10, 17]  # Key features
    
    y = []
    for i in range(n_samples):
        # Count positive indicators
        phishing_score = sum(X[i][j] for j in phishing_indicators if X[i][j] == 1)
        # Add some randomness
        phishing_score += np.random.normal(0, 0.5)
        # Classify: 1 for phishing, -1 for legitimate
        y.append(1 if phishing_score > 2 else -1)
    
    y = np.array(y)
    
    # Create DataFrame with proper column names
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df['class'] = y
    
    return df

def train_logistic_regression_model():
    """Train a logistic regression model on the synthetic dataset."""
    # Create or load dataset
    data = create_synthetic_dataset()
    
    # Separate features and target
    X = data.drop('class', axis=1)
    y = data['class']
    
    # Convert labels from -1/1 to 0/1 for sklearn
    y_binary = (y == 1).astype(int)
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
    )
    
    # Train logistic regression
    model = LogisticRegression(random_state=42, max_iter=1000)
    model.fit(X_train, y_train)
    
    # Calculate accuracy
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"Logistic Regression Accuracy: {accuracy:.4f}")
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    
    return model, accuracy

def save_model(model, accuracy, filename='phishing_model.pkl'):
    """Save the trained model to a file."""
    model_data = {
        'model': model,
        'accuracy': accuracy,
        'feature_names': FEATURE_NAMES
    }
    with open(filename, 'wb') as f:
        pickle.dump(model_data, f)

def load_model(filename='phishing_model.pkl'):
    """Load a trained model from a file."""
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            model_data = pickle.load(f)
        return model_data['model'], model_data['accuracy']
    return None, None

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'message': 'Phishing URL Detection API - Colab Model',
        'version': '1.0',
        'model_accuracy': f'{accuracy:.4f}' if accuracy else 'Model not loaded',
        'features': len(FEATURE_NAMES),
        'endpoints': {
            'predict': 'POST /predict - Analyze a URL for phishing',
            'health': 'GET /health - Check API health',
            'model_info': 'GET /model_info - Get model information'
        }
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy', 
        'message': 'Colab-compatible Phishing Detection API is running',
        'model_loaded': model is not None,
        'accuracy': f'{accuracy:.4f}' if accuracy else 'N/A'
    })

@app.route('/model_info', methods=['GET'])
def model_info():
    return jsonify({
        'model_type': 'Logistic Regression',
        'features': FEATURE_NAMES,
        'feature_count': len(FEATURE_NAMES),
        'accuracy': f'{accuracy:.4f}' if accuracy else 'N/A',
        'description': 'Model trained on phishing URL detection dataset with 30 features'
    })

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
        
        # Extract features using our feature extractor
        features = extract_features_for_colab_model(url)
        
        # Convert to numpy array and reshape
        features_array = np.array(features).reshape(1, -1)
        
        # Make prediction
        global model, accuracy
        if model is None:
            return jsonify({'error': 'Model not loaded'}), 500
        
        prediction = model.predict(features_array)[0]
        probabilities = model.predict_proba(features_array)[0]
        
        # Calculate confidence
        confidence = max(probabilities)
        
        # Determine result (prediction is 0 or 1, convert back to our format)
        is_phishing = bool(prediction)
        
        # Create detailed response
        response = {
            'url': url,
            'is_phishing': is_phishing,
            'confidence': float(confidence),
            'prediction': int(prediction),
            'probabilities': {
                'safe': float(probabilities[0]),
                'phishing': float(probabilities[1])
            },
            'features_extracted': {
                name: int(value) for name, value in zip(FEATURE_NAMES, features)
            },
            'model_info': {
                'type': 'Logistic Regression',
                'accuracy': f'{accuracy:.4f}' if accuracy else 'N/A'
            },
            'recommendation': (
                'AVOID - This URL shows signs of being malicious' if is_phishing 
                else 'PROCEED WITH CAUTION - This URL appears to be safe' if confidence < 0.8 
                else 'SAFE - This URL appears to be legitimate'
            )
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({'error': f'Error processing request: {str(e)}'}), 500

if __name__ == '__main__':
    print("=" * 50)
    print("Starting Colab-compatible Phishing URL Detection API")
    print("=" * 50)
    
    # Try to load existing model
    print("Checking for existing model...")
    model, accuracy = load_model()
    
    if model is None:
        print("No existing model found. Training new model...")
        model, accuracy = train_logistic_regression_model()
        
        # Save the model
        print("Saving trained model...")
        save_model(model, accuracy)
        print(f"Model saved with accuracy: {accuracy:.4f}")
    else:
        print(f"Loaded existing model with accuracy: {accuracy:.4f}")
    
    print("=" * 50)
    print(f"Model ready! Accuracy: {accuracy:.4f}")
    print("API available at http://localhost:5001")
    print("Features extracted:", len(FEATURE_NAMES))
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5001)
