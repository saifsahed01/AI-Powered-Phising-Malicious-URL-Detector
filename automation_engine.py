import pandas as pd
import re
import tldextract
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score


def extract_features(url):
    if not url:
        url = ""
    url_lower = url.lower().strip()
    
    # Domain extraction
    if '://' in url_lower:
        domain_part = url_lower.split('://')[1].split('/')[0]
    else:
        domain_part = url_lower.split('/')[0]
    domain = domain_part.replace('www.', '')
    
    features = {
        'length_url': len(url),
        'length_hostname': len(domain_part),
        'ip': 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0,
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_or': url.count('|'),
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': url.count('*'),
        'nb_colon': url.count(':'),
        'nb_comma': url.count(','),
        'nb_semicolumn': url.count(';'),
        'nb_dollar': url.count('$'),
        'nb_space': url.count(' '),
        'nb_www': 1 if 'www.' in url_lower else 0,
        'nb_com': 1 if '.com' in url_lower else 0,
        'nb_dslash': 1 if '//' in url else 0,
        'http_in_path': 1 if 'http' in url_lower.split('://')[-1] else 0,
        'https_token': 1 if url_lower.startswith('https') else 0,
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        'ratio_digits_host': sum(c.isdigit() for c in domain_part) / len(domain_part) if domain_part else 0,
        'punycode': 1 if 'xn--' in url_lower else 0,
        'port': 1 if re.search(r':\d{2,5}', url) else 0,
        'abnormal_subdomain': 1 if any(c in domain_part for c in ['-', '_']) or sum(c.isdigit() for c in domain_part[:8]) >= 2 else 0,
        'nb_subdomains': domain_part.count('.') - 1 if domain_part.count('.') > 1 else 0,
        'prefix_suffix': 1 if '-' in domain else 0,
        'shortening_service': 1 if any(s in url_lower for s in ['bit.ly','tinyurl','t.co','goo.gl']) else 0,
        'path_extension': 1 if re.search(r'\.(php|html|asp|jsp|aspx)', url_lower) else 0,
        'nb_redirection': max(0, url_lower.count('//') - 1),
        'length_words_raw': len(re.findall(r'\w+', url)),
        'char_repeat': max([url_lower.count(c) for c in set(url_lower) if c.isalnum()], default=0),
        
        # Smart typo-squatting features (model will learn from data)
        'phish_hints': sum(1 for w in ['login','verify','secure','account','update','bank','confirm','support'] if w in url_lower),
        'suspicious_domain': 1 if re.search(r'faecbook|facebok|facbook|g00gle|paypa1|arnazon|microsof|twittter|instagrm|youtub|whattsapp', domain) or 
                               sum(c.isdigit() for c in domain) >= 2 or 
                               len(re.sub(r'[aeiou]', '', domain)) > len(domain) * 0.7 else 0,
        'domain_in_brand': 1 if any(brand in domain for brand in ['facebook','google','paypal','amazon','microsoft','apple']) else 0,
    }
    
    # Fill all remaining columns expected by the model
    other_cols = ['random_domain','shortest_words_raw','shortest_word_host','shortest_word_path',
                  'longest_words_raw','longest_word_host','longest_word_path','avg_words_raw',
                  'avg_word_host','avg_word_path','brand_in_path','suspecious_tld','statistical_report',
                  'nb_hyperlinks','ratio_intHyperlinks','ratio_extHyperlinks','ratio_nullHyperlinks',
                  'nb_extCSS','ratio_intRedirection','ratio_extRedirection','ratio_intErrors',
                  'ratio_extErrors','login_form','external_favicon','links_in_tags','submit_email',
                  'ratio_intMedia','ratio_extMedia','sfh','iframe','popup_window','safe_anchor',
                  'onmouseover','right_clic','empty_title','domain_in_title','domain_with_copyright',
                  'whois_registered_domain','domain_registration_length','domain_age','web_traffic',
                  'dns_record','google_index','page_rank','brand_in_subdomain','tld_in_subdomain',
                  'tld_in_path']
    
    for col in other_cols:
        if col not in features:
            features[col] = 0
            
    return features


def train_pipeline():
    print("🚀 Training model...")
    df = pd.read_csv('Training_New (1).csv')
    
    feature_cols = [col for col in df.columns if col not in ['url', 'status']]
    X = df[feature_cols]
    y = df['status'].map({'legitimate': 0, 'phishing': 1})
    
    model = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
    model.fit(X, y)   # Train on full data for better performance
    
    joblib.dump(model, 'phishing_model.pkl')
    joblib.dump(feature_cols, 'model_features.pkl')
    print("✅ Model trained and saved successfully!")


def predict_url(url):
    url_lower = url.lower()
    
    # Strong rule-based check for obvious typos
    if any(typo in url_lower for typo in ['faecbook', 'facebok', 'facbook', 'faceb00k', 'g00gle', 'paypa1', 'arnazon']):
        return "PHISHING", 0.95
    
    model = joblib.load('phishing_model.pkl')
    feature_cols = joblib.load('model_features.pkl')
    
    feat = extract_features(url)
    df_feat = pd.DataFrame([feat]).reindex(columns=feature_cols, fill_value=0)
    
    pred = model.predict(df_feat)[0]
    prob = model.predict_proba(df_feat)[0][1]
    
    return "PHISHING" if pred == 1 else "LEGITIMATE", prob


if __name__ == "__main__":
    train_pipeline()