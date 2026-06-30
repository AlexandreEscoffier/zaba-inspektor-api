from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os

app = Flask(__name__)
CORS(app)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

@app.route("/")
def home():
    return {
        "app": "Zaba Inspektor API",
        "status": "online"
    }

@app.route("/health")
def health():
    return "OK", 200

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Aucune URL fournie."}), 400

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=8, allow_redirects=True)

        results = []
        score = 0

        for header in SECURITY_HEADERS:
            present = header in response.headers

            if present:
                score += 1

            results.append({
                "name": header,
                "present": present,
                "value": response.headers.get(header, "")
            })

        return jsonify({
            "url": url,
            "status_code": response.status_code,
            "score": score,
            "total": len(SECURITY_HEADERS),
            "results": results
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)