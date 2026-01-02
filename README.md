# 🛡️ Trustify - AI Phishing Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green?style=for-the-badge&logo=flask&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![OpenAI](https://img.shields.io/badge/OpenAI-412991?style=for-the-badge&logo=openai&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)

**Verify Links Instantly. Protect yourself from fake domains, brand impersonation, and malicious websites in real-time.**

</div>

---

## 📖 Overview

**Trustify** is a cutting-edge cybersecurity tool designed to combat the rising threat of phishing attacks. By leveraging a hybrid approach of **Machine Learning (LinearSVC)** and **Generative AI (OpenAI)**, Trustify doesn't just tell you if a link is bad—it tells you _why_.

The system analyzes URL patterns, fetches real-time domain registration data (WHOIS), and generates comprehensive PDF security reports, making it an essential tool for both individuals and security analysts.

---

## ✨ Key Features

### 🔍 Intelligent Analysis

- **Real-Time Detection:** Instantly classifies URLs as "Phishing" or "Legitimate" with high accuracy.
- **Hybrid AI Engine:** Combines TF-IDF vectorization + LinearSVC for speed, and OpenAI for contextual understanding.
- **Domain Forensics:** Automatically performs WHOIS lookups to check domain age, registrar, and expiry data.

### 📊 Detailed Reporting

- **AI-Powered Explanations:** Get natural language insights on why a specific URL was flagged.
- **PDF Reports:** Generate and download professional security reports for documentation or sharing.
- **Visual Indicators:** Clear, color-coded results (Safe/Suspicious/Phishing) for immediate decision-making.

### 💻 Modern Interface

- **Clean UI/UX:** Built with a responsive design using modern CSS and Inter font.
- **Fast Performance:** Lightweight Flask backend ensures rapid response times.

---

## 🛠️ Tech Stack

| Component     | Technology         | Description                              |
| :------------ | :----------------- | :--------------------------------------- |
| **Backend**   | Python, Flask      | Core application logic and API handling  |
| **ML Model**  | Scikit-learn       | LinearSVC model trained on 500k+ URLs    |
| **NLP**       | TF-IDF             | Feature extraction from URL strings      |
| **GenAI**     | OpenAI API         | Generates human-readable threat analysis |
| **Data**      | Pandas, NumPy      | Data manipulation and preprocessing      |
| **Utilities** | Python-whois, FPDF | Domain lookup and PDF generation         |
| **Frontend**  | HTML5, CSS3, JS    | Responsive user interface                |

---

## 📂 Project Structure

```bash
Trustify-Phishing-Detection/
├── app.py                  # 🚀 Main Flask application entry point
├── model.ipynb             # 📓 Jupyter notebook for model training & evaluation
├── phishing_url_model.pkl  # 🧠 Pre-trained Machine Learning model
├── tfidf_vectorizer.pkl    # 🔢 Saved TF-IDF Vectorizer
├── requirements.txt        # 📦 List of Python dependencies
├── .env                    # 🔑 Environment variables (API keys)
├── dataset/                # 📊 Training datasets (CSV)
├── static/                 # 🎨 Static assets (CSS, JS, Images)
├── templates/              # 📄 HTML Templates (Jinja2)
└── README.md               # 📝 Project documentation
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Git

### Installation

1.  **Clone the repository**

    ```bash
    git clone https://github.com/yourusername/Trustify-Phishing-Detection.git
    cd Trustify-Phishing-Detection
    ```

2.  **Create a Virtual Environment**

    ```bash
    # Windows
    python -m venv venv
    venv\Scripts\activate

    # macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment**
    Create a `.env` file in the root directory and add your OpenAI API key:

    ```env
    OPENAI_API_KEY=sk-your_openai_api_key_here
    ```

5.  **Run the Application**

    ```bash
    python app.py
    ```

6.  **Access the Dashboard**
    Open your browser and navigate to: `http://127.0.0.1:5000`

---

## 🧠 Model Architecture

The core detection engine is built on a **Linear Support Vector Classifier (LinearSVC)**.

1.  **Data Collection:** Trained on a balanced dataset of legitimate and phishing URLs.
2.  **Preprocessing:** URLs are tokenized and vectorized using **TF-IDF** (Term Frequency-Inverse Document Frequency).
3.  **Training:** The model learns to distinguish patterns (e.g., excessive hyphens, IP addresses, suspicious subdomains).
4.  **Inference:** New URLs are vectorized and passed through the model for a binary classification (0: Safe, 1: Phishing).

---

## 🔮 Future Scope

- [ ] Browser Extension integration.
- [ ] Deep Learning (LSTM/CNN) for improved accuracy on obfuscated URLs.
- [ ] API endpoint for external developers.
- [ ] User dashboard with history of scanned URLs.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

## 👨‍💻 Author

**Shreedhar Khorate**

<div align="center">
  <p>Made with ❤️ for a safer internet</p>
</div>
