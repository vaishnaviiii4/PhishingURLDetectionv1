import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
import tldextract

# Feature names from your Colab dataset (30 features)
FEATURE_NAMES = [
    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
    'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL',
    'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
    'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
    'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
    'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
]

def extract_features_for_colab_model(url):
    """
    Extract features matching the Colab dataset structure.
    Returns a list of 30 features with values -1, 0, or 1.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        scheme = parsed.scheme
    except:
        return [0] * 30  # Return neutral features if parsing fails
    
    features = []
    
    # 1. UsingIP - Check if URL uses IP address instead of domain name
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features.append(1 if re.match(ip_pattern, domain.replace('www.', '')) else -1)
    
    # 2. LongURL - Check URL length
    if len(url) < 54:
        features.append(-1)  # Short URL
    elif len(url) < 75:
        features.append(0)   # Medium URL
    else:
        features.append(1)   # Long URL (suspicious)
    
    # 3. ShortURL - Check if using URL shortening service
    shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link', 'ow.ly', 'is.gd', 'tiny.cc']
    features.append(1 if any(service in domain for service in shortening_services) else -1)
    
    # 4. Symbol@ - Check for @ symbol in URL
    features.append(1 if '@' in url else -1)
    
    # 5. Redirecting// - Check for "//" in path (excluding protocol)
    features.append(1 if '//' in path else -1)
    
    # 6. PrefixSuffix- - Check for prefix-suffix separated by dash in domain
    extracted = tldextract.extract(url)
    domain_without_tld = extracted.domain
    features.append(1 if '-' in domain_without_tld else -1)
    
    # 7. SubDomains - Check number of subdomains
    subdomain_count = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
    if subdomain_count <= 1:
        features.append(-1)
    elif subdomain_count == 2:
        features.append(0)
    else:
        features.append(1)  # Too many subdomains
    
    # 8. HTTPS - Check for HTTPS
    if scheme == 'https':
        features.append(-1)  # Good
    elif scheme == 'http':
        features.append(1)   # Suspicious
    else:
        features.append(0)   # Neutral
    
    # 9. DomainRegLen - Simplified domain registration length (placeholder)
    # In real implementation, you'd use WHOIS data
    features.append(-1 if len(domain) < 10 else 1)
    
    # 10. Favicon - Placeholder (would need to check actual favicon)
    features.append(0)  # Neutral as we can't easily check
    
    # 11. NonStdPort - Check for non-standard ports
    features.append(1 if ':' in parsed.netloc and not parsed.netloc.endswith(':80') and not parsed.netloc.endswith(':443') else -1)
    
    # 12. HTTPSDomainURL - Check if HTTPS is used correctly with domain
    features.append(-1 if scheme == 'https' else 1)
    
    # 13. RequestURL - Placeholder (would need to analyze page content)
    features.append(0)
    
    # 14. AnchorURL - Placeholder (would need to analyze page content)
    features.append(0)
    
    # 15. LinksInScriptTags - Placeholder (would need to analyze page content)
    features.append(0)
    
    # 16. ServerFormHandler - Placeholder (would need to analyze page content)
    features.append(0)
    
    # 17. InfoEmail - Placeholder (would need to analyze page content)
    features.append(0)
    
    # 18. AbnormalURL - Check if URL is abnormal
    # Simple check: if it contains suspicious patterns
    suspicious_patterns = ['secure', 'account', 'update', 'login', 'verify', 'suspend']
    features.append(1 if any(pattern in domain for pattern in suspicious_patterns) else -1)
    
    # 19. WebsiteForwarding - Placeholder
    features.append(0)
    
    # 20. StatusBarCust - Placeholder (would need JavaScript analysis)
    features.append(0)
    
    # 21. DisableRightClick - Placeholder (would need JavaScript analysis)  
    features.append(0)
    
    # 22. UsingPopupWindow - Placeholder (would need JavaScript analysis)
    features.append(0)
    
    # 23. IframeRedirection - Placeholder (would need page content analysis)
    features.append(0)
    
    # 24. AgeofDomain - Simplified age check (placeholder)
    # Suspicious if domain looks new/temporary
    looks_new = any(keyword in domain for keyword in ['temp', 'test', '2023', '2024', '2025'])
    features.append(1 if looks_new else -1)
    
    # 25. DNSRecording - Placeholder (would need DNS lookup)
    features.append(0)
    
    # 26. WebsiteTraffic - Placeholder (would need traffic analysis)
    features.append(0)
    
    # 27. PageRank - Placeholder (would need PageRank data)
    features.append(0)
    
    # 28. GoogleIndex - Placeholder (would need search index check)
    features.append(0)
    
    # 29. LinksPointingToPage - Placeholder (would need backlink analysis)
    features.append(0)
    
    # 30. StatsReport - Placeholder (would need statistical analysis)
    features.append(0)
    
    return features

def create_feature_dataframe(url):
    """Create a pandas DataFrame with the features for the URL."""
    features = extract_features_for_colab_model(url)
    df = pd.DataFrame([features], columns=FEATURE_NAMES)
    return df
