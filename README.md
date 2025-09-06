# Phishing URL Detection Web Application

A full-stack web application for detecting phishing URLs using machine learning, built with React frontend and Flask backend.

## Features

- **Machine Learning Model**: Logistic Regression with 92.18% accuracy
- **Real-time Analysis**: Instant URL phishing detection
- **30 Feature Extraction**: Comprehensive URL analysis
- **Modern UI**: Clean React interface with risk indicators
- **Detailed Results**: Confidence scores and risk factors

## Tech Stack

### Backend
- **Flask**: Python web framework
- **scikit-learn**: Machine learning library
- **Logistic Regression**: ML model with 30 features
- **Feature Extraction**: URL analysis (IP detection, HTTPS, domain analysis, etc.)

### Frontend  
- **React**: Modern UI framework
- **Vite**: Fast build tool
- **CSS3**: Custom styling with gradients and animations

## Quick Start

### Backend Setup
```bash
cd flask-backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python colab_model_app.py
```

### Frontend Setup
```bash
cd phishing-detector-frontend
npm install
npm run dev
```

## API Endpoints

- `POST /predict` - Analyze URL for phishing
- `GET /health` - Check API status
- `GET /model_info` - Get model details

## Usage

1. Start the Flask backend (runs on http://localhost:5001)
2. Start the React frontend (runs on http://localhost:5173) 
3. Enter a URL to analyze
4. Get instant results with confidence scores

## Model Performance

- **Accuracy**: 92.18%
- **Features**: 30 URL characteristics
- **Training Data**: 11,054 samples
- **Algorithm**: Logistic Regression

## Project Structure

```
├── flask-backend/          # Python Flask API
│   ├── colab_model_app.py  # Main Flask application
│   ├── feature_extractor.py # URL feature extraction
│   └── requirements.txt    # Python dependencies
└── phishing-detector-frontend/ # React frontend
    ├── src/
    │   ├── App.jsx        # Main React component
    │   └── App.css        # Styles
    └── package.json       # Node dependencies
```
