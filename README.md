# 🛡️ Trustify - Phishing Detection System

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/framework-Flask-green)
![Status](https://img.shields.io/badge/status-Active-success)

**Trustify** is a machine learning-based web application designed to detect and analyze phishing URLs in real-time. By combining traditional ML algorithms with Generative AI, it provides users with accurate threat assessments and detailed security reports to protect against cyber threats.

---

## 🚀 Key Features

- **Real-Time URL Analysis:** Instantly classifies URLs as "Phishing" or "Legitimate" using a trained Machine Learning model.
- **Hybrid AI Approach:** Utilizes **TF-IDF** for feature extraction and a **Linear Support Vector Classifier (SVC)** for high-accuracy classification.
- **Generative AI Insights:** Integrated with **OpenAI** to provide natural language explanations of _why_ a specific URL is flagged as dangerous.
- **Domain Intelligence:** Performs **WHOIS lookups** to gather domain age, registrar, and other metadata to support the risk assessment.
- **Automated Reporting:** Generates downloadable **PDF security reports** summarizing the analysis results for the user.
- **User-Friendly Interface:** A clean, responsive web interface built with **Flask**, HTML, CSS, and JavaScript.

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask
- **Machine Learning:** Scikit-learn (LinearSVC, TfidfVectorizer), Pandas, NumPy
- **AI Integration:** OpenAI API
- **Utilities:** Joblib (Model persistence), Python-whois (Domain info), FPDF (Report generation)
- **Frontend:** HTML5, CSS3, JavaScript

---

## 📂 Project Structure

```
Trustify-Phishing-Detection/
├── app.py                  # Main Flask application
├── model.ipynb             # Jupyter notebook for model training
├── phishing_url_model.pkl  # Trained ML model
├── tfidf_vectorizer.pkl    # TF-IDF Vectorizer
├── requirements.txt        # Python dependencies
├── dataset/                # Training datasets
├── static/                 # CSS, JS, and images
├── templates/              # HTML templates
└── README.md               # Project documentation
```

## ⚙️ Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/yourusername/Trustify-Phishing-Detection.git
    cd Trustify-Phishing-Detection
    ```

2.  **Create a virtual environment (optional but recommended):**

    ```bash
    python -m venv venv
    # Windows
    venv\Scripts\activate
    # Mac/Linux
    source venv/bin/activate
    ```

3.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up Environment Variables:**
    Create a `.env` file in the root directory and add your OpenAI API key:

    ```env
    OPENAI_API_KEY=your_api_key_here
    ```

5.  **Run the Application:**
    ```bash
    python app.py
    ```
    Access the app at `http://127.0.0.1:5000`.

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Shreedhar Khorate**
