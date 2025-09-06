#!/bin/bash

echo "Starting Phishing URL Detection Backend..."
echo "==============================================="

# Activate virtual environment
source venv/bin/activate

# Start the Flask server
echo "Running Enhanced Flask API on http://localhost:5001"
echo "Press Ctrl+C to stop the server"
echo ""

python enhanced_app.py
