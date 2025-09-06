import { useState } from 'react'
import './App.css'

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const analyzeUrl = async (e) => {
    e.preventDefault()
    
    if (!url.trim()) {
      setError('Please enter a URL')
      return
    }

    setLoading(true)
    setError('')
    setResult(null)

    try {
      const response = await fetch('https://phishingurldetectionv1.onrender.com/predict', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url.trim() })
      })

      const data = await response.json()
      
      if (response.ok) {
        setResult(data)
      } else {
        setError(data.error || 'Failed to analyze URL')
      }
    } catch (err) {
      setError('Failed to connect to server. Please check your internet connection.')
    } finally {
      setLoading(false)
    }
  }

  const resetForm = () => {
    setUrl('')
    setResult(null)
    setError('')
  }

  return (
    <div className="app">
      <div className="container">
        <header className="header">
          <h1>Phishing URL Detection</h1>
          <p>Enter a URL to check if it's safe or potentially malicious</p>
        </header>

        <form onSubmit={analyzeUrl} className="form">
          <div className="input-group">
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL (e.g., https://example.com)"
              className="url-input"
              disabled={loading}
            />
            <button 
              type="submit" 
              className="analyze-btn"
              disabled={loading || !url.trim()}
            >
              {loading ? 'Analyzing...' : 'Analyze URL'}
            </button>
          </div>
        </form>

        {error && (
          <div className="error">
            <p>{error}</p>
          </div>
        )}

        {result && (
          <div className="result">
            <div className={`status ${result.is_phishing ? 'malicious' : 'safe'}`}>
              <h2>{result.is_phishing ? 'MALICIOUS' : 'SAFE'}</h2>
              <p className="confidence">
                Confidence: {(result.confidence * 100).toFixed(1)}%
              </p>
            </div>
            <div className="details">
              <p><strong>URL:</strong> {result.url}</p>
              <p><strong>Recommendation:</strong> {result.recommendation || (result.is_phishing ? 'Potentially dangerous - avoid visiting' : 'Appears to be safe')}</p>
              
              {result.risk_factors && result.risk_factors.length > 0 && (
                <div className="risk-factors">
                  <p><strong>Risk Factors Detected:</strong></p>
                  <ul>
                    {result.risk_factors.map((factor, index) => (
                      <li key={index}>{factor}</li>
                    ))}
                  </ul>
                </div>
              )}
              
              <div className="probabilities">
                <p><strong>Detailed Analysis:</strong></p>
                <div className="probability-bars">
                  <div className="probability-item">
                    <span>Safe: {(result.probabilities.safe * 100).toFixed(1)}%</span>
                    <div className="probability-bar">
                      <div 
                        className="probability-fill safe-fill" 
                        style={{width: `${result.probabilities.safe * 100}%`}}
                      ></div>
                    </div>
                  </div>
                  <div className="probability-item">
                    <span>Phishing: {(result.probabilities.phishing * 100).toFixed(1)}%</span>
                    <div className="probability-bar">
                      <div 
                        className="probability-fill danger-fill" 
                        style={{width: `${result.probabilities.phishing * 100}%`}}
                      ></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <button onClick={resetForm} className="reset-btn">
              Check Another URL
            </button>
          </div>
        )}

        {loading && (
          <div className="loading">
            <div className="spinner"></div>
            <p>Analyzing URL...</p>
          </div>
        )}
      </div>
    </div>
  )
}

export default App
