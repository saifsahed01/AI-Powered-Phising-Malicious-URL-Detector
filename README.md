# 🛡️ AI-Powered Phishing & Malicious URL Detector

A modern web application that uses Machine Learning to detect phishing and malicious URLs in real-time.

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-FF9F1C?style=for-the-badge&logo=scikit-learn&logoColor=white)

---

## ✨ Features

- Fast URL scanning
- Advanced typo-squatting detection (e.g. `faecbook.com`, `g00gle.com`)
- Random Forest Machine Learning Model
- Clean and user-friendly interface
- Trained on real phishing dataset

---

## 🚀 How to Run Locally

1. Clone the repo:
```bash
git clone https://github.com/saifsahed01/AI-Powered-Phising-Malicious-URL-Detector.git
cd AI-Powered-Phising-Malicious-URL-Detector

Install requirements:

Bashpip install pandas numpy tldextract scikit-learn joblib streamlit

Train the model:

Bashpython automation_engine.py

Start the app:

Bashstreamlit run app.py

📁 Project Structure
text├── app.py                    # Streamlit Web Interface
├── automation_engine.py      # Feature extraction + ML training
├── Training_New (1).csv      # Training dataset
├── phishing_model.pkl        # Trained model (auto-generated)
├── model_features.pkl        # Feature list
└── README.md

🧠 How It Works
The system extracts 50+ features from any URL (length, special characters, suspicious patterns, brand impersonation, etc.) and classifies it using a trained Random Forest model.

📄 License
MIT License © 2026 Saif Sahed

Made for educational and cybersecurity awareness purposes.
