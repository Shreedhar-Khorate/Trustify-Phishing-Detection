from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
import joblib
import os
from dotenv import load_dotenv
from urllib.parse import urlparse
import difflib
import google.generativeai as genai
from fpdf import FPDF
import whois
from datetime import datetime

# =========================
# Helpers
# =========================
def clean_text(text):
    # Remove markdown noise that clutters UI
    for ch in ["#", "*", "`", "_"]:
        text = text.replace(ch, "")
    return text.strip()

def clean_for_pdf(text):
    # Replace unsupported characters for basic FPDF
    replacements = {
        "⚠️": "[!]", "✅": "[OK]", "🚨": "[!]", "✨": "*", "📊": "", "⚡": "", "🔍": "", "🛡️": "", "🎣": "", "🚩": ""
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    # Encode to latin-1, ignoring errors to prevent crashes
    return text.encode('latin-1', 'ignore').decode('latin-1')



def to_native(val):
    """Convert numpy / pandas scalars to plain Python types for JSON safety."""
    try:
        import numpy as np
        if isinstance(val, (np.generic,)):
            return val.item()
    except Exception:
        pass
    if isinstance(val, bool):
        return bool(val)
    if isinstance(val, (int, float, str)):
        return val
    return val

# =========================
# Load Environment
# =========================
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
gemini_model = genai.GenerativeModel('gemini-2.5-flash')

# =========================
# Known Brands
# =========================
KNOWN_BRANDS = [
    "google", "facebook", "amazon", "paypal", "microsoft",
    "apple", "netflix", "instagram", "whatsapp",
    "linkedin", "bank", "outlook", "yahoo"
]

# =========================
# Recent Scans Storage
# =========================
RECENT_SCANS = []

# =========================
# Domain Age (Whois)
# =========================
def get_domain_age(url):
    try:
        domain = urlparse(url if "://" in url else f"http://{url}").netloc
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            if isinstance(creation_date, str):
                try:
                    creation_date = datetime.strptime(creation_date, "%Y-%m-%d %H:%M:%S")
                except:
                    return None
            age = (datetime.now() - creation_date).days
            return age
    except Exception:
        pass
    return None

# =========================
# Typosquatting Detection
# =========================
def assess_typosquat(url):
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()

    if not host:
        return False, []

    parts = host.split(".")
    candidate = parts[-2] if len(parts) >= 2 else host

    leet = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})
    normalized = candidate.translate(leet)

    reasons = []
    seen = set()
    for brand in KNOWN_BRANDS:
        # Exact known brand domain is fine; skip it
        if candidate == brand:
            continue

        if normalized == brand:
            msg = f"Domain '{candidate}' imitates '{brand}' (typosquatting)."
            if msg not in seen:
                reasons.append(msg)
                seen.add(msg)
        else:
            similarity = difflib.SequenceMatcher(None, candidate, brand).ratio()
            if similarity >= 0.7:
                msg = f"Domain '{candidate}' resembles '{brand}' (brand impersonation)."
                if msg not in seen:
                    reasons.append(msg)
                    seen.add(msg)

    return len(reasons) > 0, reasons

# =========================
# URL Feature Extraction
# =========================
def extract_url_features(url):
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()
    parts = host.split(".") if host else []

    features = {
        "scheme": parsed.scheme or "http",
        "netloc": host,
        "url_length": len(url),
        "domain_length": len(host),
        "subdomain_count": max(len(parts) - 2, 0),
        "path_length": len(parsed.path or ""),
        "query_length": len(parsed.query or ""),
        "digit_count": sum(ch.isdigit() for ch in url),
        "https": parsed.scheme == "https",
    }

    caps = {
        "url_length": 200,
        "domain_length": 60,
        "subdomain_count": 6,
        "path_length": 120,
        "query_length": 160,
        "digit_count": 25,
    }

    for k, cap in caps.items():
        features[f"{k}_pct"] = min(features[k] / cap, 1) * 100

    return features

# =========================
# Risk Score
# =========================
def compute_risk_score(prediction, heuristic_flag, f):
    score = 50
    score += 35 if prediction == 1 else -15
    if heuristic_flag: score += 25
    if f["digit_count"] > 3: score += 5
    if f["subdomain_count"] > 1: score += 5
    if not f["https"]: score += 8
    if f["url_length"] > 80: score += 5

    score = max(0, min(100, score))
    label = "High Risk" if score >= 70 else "Moderate Risk" if score >= 40 else "Low Risk"
    return score, label

# =========================
# Load ML Model
# =========================
try:
    model = joblib.load("phishing_url_model.pkl")
    vectorizer = joblib.load("tfidf_vectorizer.pkl")
    MODEL_LOADED = True
except Exception as e:
    print(f"Warning: Model files not found or incompatible. Using heuristics only. Error: {e}")
    model = None
    vectorizer = None
    MODEL_LOADED = False

# =========================
# Flask App
# =========================
app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/index.html')
def index_html():
    return render_template("index.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Missing URL"}), 400

    heuristic_flag, heuristic_reasons = assess_typosquat(url)
    heuristic_reasons = list(dict.fromkeys(heuristic_reasons))  # dedupe
    url_features = extract_url_features(url)

    pred = 0
    if MODEL_LOADED:
        try:
            pred_raw = model.predict(vectorizer.transform([url]))[0]
            pred = int(to_native(pred_raw))
        except Exception as e:
            print(f"Prediction error: {e}")
            # Continue with 0 (Legitimate) from model, relying on heuristics

    result = "Suspicious" if pred == 1 or heuristic_flag else "Legitimate"

    # Domain Age Check
    domain_age = get_domain_age(url)
    if domain_age is not None and domain_age < 30:
        heuristic_reasons.append(f"Domain is very new ({domain_age} days old).")
        # If it's new, it's likely suspicious regardless of model
        if result == "Legitimate":
            result = "Suspicious"

    risk_score, risk_label = compute_risk_score(
        1 if result.startswith("Suspicious") else 0,
        heuristic_flag,
        url_features
    )

    if domain_age is not None and domain_age < 30:
        risk_score += 20

    risk_score = int(to_native(risk_score))
    risk_score = min(100, risk_score) # Cap at 100

    url_features = {k: to_native(v) for k, v in url_features.items()}

    # Add to recent scans
    scan_entry = {
        "url": url,
        "result": result,
        "score": risk_score,
        "time": datetime.now().strftime("%H:%M")
    }
    RECENT_SCANS.insert(0, scan_entry)
    if len(RECENT_SCANS) > 5:
        RECENT_SCANS.pop()

    ai_suggestion = None

    try:
        prompt = f"""
You are a cybersecurity analyst.

Analyze the URL below and decide if it is Phishing or Legitimate.

URL: {url}
System Prediction: {result}

Explain:
- Domain similarity / impersonation
- URL structure and patterns
- HTTPS usage

Return:
Analysis Summary:
Risk Factors:
Final Verdict:
Recommendation:
"""

        response = gemini_model.generate_content(prompt)
        ai_suggestion = clean_text(response.text)

    except Exception as e:
        print(f"Gemini API Error: {e}")
        if "429" in str(e) or "quota" in str(e).lower():
            ai_suggestion = "Gemini API rate limit or quota exceeded."
        else:
            ai_suggestion = "Gemini API unavailable."

    return jsonify({
        "result": result,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "heuristic_reasons": heuristic_reasons,
        "url_features": url_features,
        "ai_suggestion": ai_suggestion,
        "domain_age": domain_age,
        "recent_scans": RECENT_SCANS
    })

@app.route("/api/recent", methods=["GET"])
def api_recent():
    return jsonify(RECENT_SCANS)

@app.route("/api/export-pdf", methods=["POST"])
def export_pdf():
    data = request.get_json(silent=True) or {}
    url = clean_for_pdf(data.get("url", "Unknown URL"))
    risk_score = data.get("risk_score", 0)
    risk_label = clean_for_pdf(data.get("risk_label", "Unknown"))
    ai_summary = clean_for_pdf(data.get("ai_summary", "No summary available."))
    
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Trustify Security Report", ln=True, align='C')
    pdf.ln(10)
    
    # URL Info
    pdf.set_font("Arial", "B", 12)
    pdf.cell(40, 10, "Analyzed URL:", 0)
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 10, url)
    pdf.ln(5)
    
    # Risk Score
    pdf.set_font("Arial", "B", 12)
    pdf.cell(40, 10, "Risk Score:", 0)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"{risk_score}/100 ({risk_label})", ln=True)
    pdf.ln(10)
    
    # AI Analysis
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "AI Analysis Summary", ln=True)
    pdf.ln(5)
    
    pdf.set_font("Arial", "", 11)
    pdf.multi_cell(0, 8, ai_summary)
    
    # Footer
    pdf.set_y(-30)
    pdf.set_font("Arial", "I", 8)
    pdf.cell(0, 10, "Generated by Trustify Phishing Detection System", 0, 0, 'C')
    
    filename = "Trustify_Report.pdf"
    pdf.output(filename)
    
    return send_file(filename, as_attachment=True, download_name="Trustify_Report.pdf")


@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json(silent=True) or {}
    user_msg = (data.get("message") or "").strip()

    if not user_msg:
        return jsonify({"error": "Empty message"}), 400

    try:
        system_prompt = "You are Trustify's AI Cybersecurity Assistant. Help users understand phishing, analyze URLs, and learn about online safety. Keep answers concise, professional, and helpful."
        full_prompt = f"{system_prompt}\n\nUser: {user_msg}"
        response = gemini_model.generate_content(full_prompt)
        reply = clean_text(response.text)
        return jsonify({"reply": reply})
    except Exception as e:
        print(f"Chat Error: {e}")
        return jsonify({"reply": "Sorry, I'm having trouble connecting to the server right now."})

if __name__ == "__main__":
    app.run(debug=True)
