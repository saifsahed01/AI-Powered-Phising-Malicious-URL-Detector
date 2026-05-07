import streamlit as st
import joblib
import pandas as pd
from automation_engine import extract_features, predict_url

st.set_page_config(page_title="AI Phishing Detector", page_icon="🛡️", layout="centered")

st.title("🛡️ AI Phishing URL Detector")
st.markdown("**Enter a URL to check if it's safe or malicious**")
st.markdown("---")

url = st.text_input("URL:", placeholder="https://example.com")

if st.button("🔍 Scan URL", type="primary"):
    if url:
        with st.spinner("Analyzing..."):
            result, prob = predict_url(url)
            
            if result == "PHISHING":
                st.error(f"🚨 **PHISHING DETECTED**")
                st.metric("Confidence", f"{prob:.1%}")
            else:
                st.success(f"✅ **SAFE / LEGITIMATE**")
                st.metric("Confidence", f"{(1-prob):.1%}")
            
            st.code(url, language=None)
    else:
        st.warning("Please enter a URL")

st.caption("Powered by Random Forest • Trained on real phishing dataset")