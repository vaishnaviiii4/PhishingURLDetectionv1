# Phishing URL Detection


## What it does

You paste a URL, and it tells you if it looks suspicious or safe. Pretty simple concept but surprisingly effective.

## Live Demo

- **Try it here**: https://phishing-url-detectionv1.vercel.app/
- **API**: https://phishingurldetectionv1.onrender.com

## How I built it

### Data Analysis
Started with a Kaggle dataset containing 11,000+ URLs with 30 different features. Did some EDA in a Colab notebook to understand what makes URLs suspicious - things like using IP addresses instead of domains, weird URL lengths, suspicious redirects, etc.

### Machine Learning
Tried a couple of algorithms:
- Logistic Regression - got 92.18% accuracy
- Random Forest - didn't perform as well

Went with Logistic Regression since it worked better and is easier to interpret.

### Backend
Built a Flask API that:
- Takes a URL as input
- Extracts 30 features from it
- Runs it through the trained model
- Returns prediction with confidence score

Deployed on Render.

### Frontend
Created a React app with:
- Simple URL input form
- Nice visual feedback (green for safe, red for dangerous)
- Shows confidence percentage and risk factors
- Deployed on Vercel

## Dataset

Used this dataset from Kaggle: https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector

11,054 URLs with labels and 30 features each.

## Tech Stack

- **Backend**: Flask, scikit-learn, Python
- **Frontend**: React, Vite
- **Deployment**: Render (backend), Vercel (frontend)

## Running locally

Backend:
```bash
cd flask-backend
source venv/bin/activate
python colab_model_app.py
```

Frontend:
```bash
cd phishing-detector-frontend
npm install
npm run dev
```
