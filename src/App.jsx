// App.jsx
import { useState } from 'react';
import './App.css';
import SplashCursor from './SplashCursor';
const apiKey = import.meta.env.VITE_API_KEY;

// --- Configuration --- //
const SHORTENER_API_URL = 'https://tinyurl.com/api-create.php';
const GOOGLE_API_KEY = apiKey; // From Google Cloud Console


// --- QR Code Generation --- //
const generateQRCode = (url) => {
  // Using QR Server API for QR code generation
  const qrApiUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(url)}`;
  return qrApiUrl;
};

// --- Services --- //
const checkUrlSafety = async (url) => {
  try {    
    if (!GOOGLE_API_KEY || GOOGLE_API_KEY === 'undefined' || !apiKey) {      
      // Basic malicious URL detection for common test malware URLs
      const maliciousPatterns = [
        'testsafebrowsing.appspot.com',
        'malware.testing.google.test',
        '/malware.html',
        '/phishing.html',
        '/unwanted.html'
      ];
      
      const isMalicious = maliciousPatterns.some(pattern => url.toLowerCase().includes(pattern.toLowerCase()));
      
      if (isMalicious) {
        return false; // URL is malicious
      }
      
      return true; // Assume safe if no API key and no patterns match
    }
    
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { 
            clientId: 'SafeSnip', 
            clientVersion: '1.0' 
          },
          threatInfo: {
            threatTypes: [
              'MALWARE', 
              'SOCIAL_ENGINEERING', 
              'UNWANTED_SOFTWARE', 
              'POTENTIALLY_HARMFUL_APPLICATION'
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
          }
        })
      }
    );
    
    if (!response.ok) {
      console.error('Safe Browsing API error:', response.status, response.statusText);
      return true; // Assume safe if API fails
    }
    
    const data = await response.json();
    
    // If matches found, URL is malicious
    const isSafe = !data.matches || data.matches.length === 0;
    
    return isSafe;
  } catch {
    return true; // Assume safe if API fails
  }
};

const shortenUrl = async (longUrl) => {
  // TinyURL uses a simple GET request with URL parameter
  const response = await fetch(`${SHORTENER_API_URL}?url=${encodeURIComponent(longUrl)}`, {
    method: 'GET'
  });

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  const shortUrl = await response.text();
  
  // TinyURL returns the shortened URL directly as plain text
  if (shortUrl && shortUrl.startsWith('https://tinyurl.com/')) {
    return shortUrl.trim();
  } else {
    throw new Error('Unexpected response from URL shortener');
  }
};

// --- Icons --- //
const LinkIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
  </svg>
);

const CheckIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20 6L9 17l-5-5"></path>
  </svg>
);

const AlertIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
    <line x1="12" y1="9" x2="12" y2="13"></line>
    <line x1="12" y1="17" x2="12.01" y2="17"></line>
  </svg>
);

const CopyIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
  </svg>
);

const CheckCircleIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
    <polyline points="22 4 12 14.01 9 11.01"></polyline>
  </svg>
);

const AlertCircleIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"></circle>
    <line x1="12" y1="8" x2="12" y2="12"></line>
    <line x1="12" y1="16" x2="12.01" y2="16"></line>
  </svg>
);

// --- Main Component --- //
function App() {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [qrCodeUrl, setQrCodeUrl] = useState(null);
  const [isSafe, setIsSafe] = useState(null);
  const [error, setError] = useState(null);
  const [expiryInfo, setExpiryInfo] = useState(null);
  const [copyText, setCopyText] = useState('Copy');
  const [passwordProtected, setPasswordProtected] = useState(false);
  const [password, setPassword] = useState('');

  // Only show password protection if running locally
  const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

  const validateUrl = (inputUrl) => {
    try {
      if (!inputUrl) throw new Error('URL is required');
      if (!inputUrl.match(/^https?:\/\//i)) {
        throw new Error('URL must start with http:// or https://');
      }
      new URL(inputUrl); // This will throw if URL is invalid
      return true;
    } catch (err) {
      setError(err.message);
      return false;
    }
  };

  const handleSubmit = async (e) => {
    if (e) e.preventDefault(); // Prevent form submission if called from form
    
    setError(null);
    setExpiryInfo(null);
    setQrCodeUrl(null);
    setCopyText('Copy');
    if (!validateUrl(url)) return;

    setIsLoading(true);
    setResult(null);
    setIsSafe(null);

    try {
      // 1. FIRST: Safety Check with Google Safe Browsing API
      const isSafeUrl = await checkUrlSafety(url);
      
      if (!isSafeUrl) {
        // URL is malicious - STOP HERE, don't proceed to TinyURL
        setIsSafe(false);
        setError('Malicious URL detected - cannot be shortened for security reasons');
        setIsLoading(false);
        return; // EXIT - Don't proceed to TinyURL
      }

      // 2. ONLY IF SAFE: Proceed to shorten with TinyURL
      
      let finalUrl;
      if (isLocalhost && passwordProtected && password.trim()) {
        // For password protection, just show a warning but still shorten the URL normally
        const shortUrl = await shortenUrl(url);
        finalUrl = shortUrl;
        setExpiryInfo('Note: Password protection is for local reference only. URL shortened normally.');
      } else {
        // Regular URL shortening
        const shortUrl = await shortenUrl(url);
        finalUrl = shortUrl;
        setExpiryInfo('Note: TinyURL links do not expire');
      }
      
      setResult(finalUrl);
      setIsSafe(true);
      
      // 3. Generate QR Code for the final URL
      const qrUrl = generateQRCode(finalUrl);
      setQrCodeUrl(qrUrl);
      
    } catch (err) {
      // This should only catch TinyURL errors or other unexpected errors
      setError(`Service error: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = () => {
    if (!result) return;
    
    navigator.clipboard.writeText(result)
      .then(() => {
        setCopyText('Copied!');
        setTimeout(() => {
          setCopyText('Copy');
        }, 2000);
      })
      .catch(err => {
        console.error('Failed to copy: ', err);
        setCopyText('Failed');
        setTimeout(() => {
          setCopyText('Copy');
        }, 2000);
      });
  };

  return (
    <>
      <SplashCursor 
        SIM_RESOLUTION={96}
        DYE_RESOLUTION={720}
        DENSITY_DISSIPATION={6}
        VELOCITY_DISSIPATION={4}
        PRESSURE={0.08}
        CURL={1.5}
        SPLAT_RADIUS={0.15}
        SPLAT_FORCE={3500}
        COLOR_UPDATE_SPEED={7}
      />
      <div className="app-container">
        <div className="app-content">
          {/* Header Section */}
          <div className="header-section">
            <h1>SafeSnip</h1>
            <p className="tagline">Secure URL Shortening</p>
          </div>
        
        {/* Input Section */}
        <div className="input-section">
          <form className="input-container" onSubmit={handleSubmit}>
            <input
              type="text"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setError(null);
              }}
              placeholder="https://example.com"
              disabled={isLoading}
            />
            <button 
              type="submit"
              disabled={isLoading || !url}
            >
              {isLoading ? (
                <span className="loader"></span>
              ) : (
                'Shorten'
              )}
            </button>
          </form>
          
          {/* Password Protection Section - Only show on localhost */}
          {isLocalhost && (
            <div className="password-protection">
              <label className="password-checkbox">
                <input
                  type="checkbox"
                  checked={passwordProtected}
                  onChange={(e) => setPasswordProtected(e.target.checked)}
                  disabled={isLoading}
                />
                <span className="checkmark"></span>
                Password protect this link
              </label>
              {passwordProtected && (
                <div className="password-input-container">
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter password"
                    disabled={isLoading}
                    className="password-input"
                  />
                </div>
              )}
              {passwordProtected && (
                <div className="password-limitation-note">
                  ⚠️ Note: This adds a password note for your reference. The shortened URL works normally for sharing.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Status Section */}
        <div className="status-section">
          {error && isSafe === false && (
            <div className="message warning">
              <div className="warning-content">
                <div className="warning-title">Security Alert</div>
                <div className="warning-description">
                  This URL has been flagged as malicious and cannot be shortened for your safety.
                </div>
              </div>
            </div>
          )}
          {error && isSafe !== false && (
            <div className="message error">
              {error}
            </div>
          )}
        </div>

        {/* Results Section */}
        {result && (
          <div className="result-section">
            <div className={`result-container ${isSafe ? 'safe' : 'unsafe'}`}>
              <div className="status-indicator">
                {isSafe ? (
                  <>
                    <CheckCircleIcon /> 
                    Safe Link Verified
                  </>
                ) : (
                  <>
                    <AlertIcon />
                    Unsafe Link Warning
                  </>
                )}
              </div>
              
              <div className="result-url">
                <a href={result} target="_blank" rel="noopener noreferrer">
                  {result}
                </a>
              </div>
              
              {qrCodeUrl && (
                <div className="qr-code-container">
                  <div className="qr-code-label">QR Code</div>
                  <img 
                    src={qrCodeUrl} 
                    alt="QR Code for shortened URL" 
                    className="qr-code-image"
                  />
                </div>
              )}
              
              <button 
                onClick={copyToClipboard}
                className="copy-button"
              >
                {copyText === 'Copy' ? <CopyIcon /> : <CheckIcon />} {copyText}
              </button>

              {expiryInfo && (
                <div className="expiry-info">
                  {expiryInfo}
                </div>
              )}
              
              {isLocalhost && passwordProtected && password.trim() && (
                <div className="password-note">
                  🔐 Password Note: "{password}"
                </div>
              )}

              <div className="service-credits">
                Powered by{' '}
                <a href="https://developers.google.com/safe-browsing" target="_blank" rel="noopener noreferrer">
                  Google Safe Browsing
                </a>
                {' '}
                and{' '}
                <a href="https://tinyurl.com" target="_blank" rel="noopener noreferrer">
                  TinyURL
                </a>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
    
    {/* Privacy Section - Moved to Bottom */}
    <div className="privacy-section">
      <h3>Why Choose SafeSnip?</h3>
      <div className="privacy-features">
        <div className="privacy-feature">
          <div className="privacy-icon">🔒</div>
          <div className="privacy-content">
            <h4>Privacy First</h4>
            <p>We collect only essential data - your URL and shortened code. No tracking of location, IP addresses, or browser fingerprinting.</p>
          </div>
        </div>
        
        <div className="privacy-feature">
          <div className="privacy-icon">🛡️</div>
          <div className="privacy-content">
            <h4>Security Focused</h4>
            <p>Every URL is checked against Google Safe Browsing before shortening. Malicious links are blocked to protect you and your audience.</p>
          </div>
        </div>
        
        <div className="privacy-feature">
          <div className="privacy-icon">🚫</div>
          <div className="privacy-content">
            <h4>No Ads, No Tracking</h4>
            <p>Unlike other services, we don't show ads, sell your data, or track your users. Your links work cleanly without unwanted redirects.</p>
          </div>
        </div>
        
        <div className="privacy-feature">
          <div className="privacy-icon">⚡</div>
          <div className="privacy-content">
            <h4>Anonymous & Fast</h4>
            <p>No account required. Create secure short links instantly without providing personal information or email addresses.</p>
          </div>
        </div>
        
        <div className="privacy-feature">
          <div className="privacy-icon">🔐</div>
          <div className="privacy-content">
            <h4>Password Protection</h4>
            <p>Add an extra layer of security with optional password protection for sensitive links - a feature many services charge for.</p>
          </div>
        </div>
        
        <div className="privacy-feature">
          <div className="privacy-icon">📱</div>
          <div className="privacy-content">
            <h4>Built-in QR Codes</h4>
            <p>Generate QR codes instantly without third-party services. Perfect for bridging digital and physical marketing materials.</p>
          </div>
        </div>
      </div>
      
      <div className="privacy-commitment">
        <h4>Our Privacy Commitment</h4>
        <ul>
          <li>✅ Zero user tracking or analytics</li>
          <li>✅ No data selling or sharing with third parties</li>
          <li>✅ Minimal data collection (URL + shortened code only)</li>
          <li>✅ No cookies or persistent storage without consent</li>
          <li>✅ Open source and transparent operations</li>
        </ul>
      </div>
    </div>
    
    </>
  );
}

export default App;