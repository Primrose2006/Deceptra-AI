from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib

app = Flask(__name__)
CORS(app)

model = joblib.load("models/deceptra_v2_model.pkl")
text_model = joblib.load("models/deceptra_v2_model.pkl")
url_model = joblib.load("models/url_model.pkl")

TACTICS = {
    "Fear": ["suspended", "blocked", "disabled", "locked", "terminated", "warning", "fraud", "penalty", "risk"],
    "Urgency": ["immediately", "urgent", "now", "within 24 hours", "act fast", "today", "limited time", "final notice"],
    "Authority": ["bank", "government", "official", "admin", "support team", "security department", "police", "rbi"],
    "Greed": ["won", "prize", "lottery", "reward", "cash", "bonus", "free", "cashback"],
    "Trust Exploitation": ["dear customer", "friend", "family", "manager", "boss", "verified", "trusted", "secure"],
    "Curiosity": ["secret", "exclusive", "hidden", "shocking", "click here", "see this", "surprise"],
    "Credential Theft": ["password", "otp", "pin", "login", "verify account", "credentials"],
    "Financial Scam": ["payment", "upi", "bank account", "transfer", "registration fee", "refund"]
}

def detect_tactics(text):
    text = text.lower()
    results = {}

    for tactic, words in TACTICS.items():
        matched = [word for word in words if word in text]
        if matched:
            results[tactic] = matched

    return results

def risk_level(score):
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"

@app.route("/")
def home():
    return "Deceptra AI Backend is running!"

@app.route("/routes")
def routes():
    return jsonify([str(rule) for rule in app.url_map.iter_rules()])

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    message = data.get("message", "")

    if not message.strip():
        return jsonify({"error": "Message is required"}), 400

    prediction = text_model.predict([message])[0]
    probability = text_model.predict_proba([message])[0]

    scam_probability = probability[1] * 100
    tactics = detect_tactics(message)

    threat_score = min(100, scam_probability + len(tactics) * 5)

    recommendations = []

    if "Fear" in tactics:
        recommendations.append("Do not panic. Scammers use fear to force quick decisions.")

    if "Urgency" in tactics:
        recommendations.append("Avoid acting immediately. Verify through official channels first.")

    if "Authority" in tactics:
        recommendations.append("Contact the organization directly using its official website or phone number.")

    if "Greed" in tactics:
        recommendations.append("Be careful with prizes, rewards, and offers that sound too good to be true.")

    if "Credential Theft" in tactics:
        recommendations.append("Never share passwords, OTPs, PINs, or login details.")

    if "Financial Scam" in tactics:
        recommendations.append("Do not transfer money or pay fees without verification.")

    if not recommendations:
        recommendations.append("No major manipulation pattern detected. Still verify unknown senders.")

    return jsonify({
        "prediction": "Threat / Scam" if prediction == 1 else "Safe",
        "confidence": round(scam_probability, 2),
        "threat_score": round(threat_score, 2),
        "risk_level": risk_level(threat_score),
        "tactics": tactics,
        "recommendations": recommendations
    })
@app.route("/analyze-url", methods=["POST"])
def analyze_url():
    data = request.get_json()
    url = data.get("url", "")

    if not url.strip():
        return jsonify({"error": "URL is required"}), 400

    prediction = url_model.predict([url])[0]
    probability = url_model.predict_proba([url])[0]

    confidence = max(probability) * 100

    if prediction == "benign":
        risk = "Low"
        threat_score = round(100 - confidence, 2)
    else:
        risk = "High" if prediction in ["phishing", "malware"] else "Medium"
        threat_score = round(confidence, 2)

    return jsonify({
        "url": url,
        "prediction": prediction,
        "confidence": round(confidence, 2),
        "threat_score": threat_score,
        "risk_level": risk,
        "recommendations": [
            "Do not open suspicious or shortened links.",
            "Verify the domain before entering passwords or payment details.",
            "Avoid downloading files from unknown websites."
        ]
    })

if __name__ == "__main__":
    app.run(debug=False)