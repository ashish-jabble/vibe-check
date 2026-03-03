"""
VibeCheck — Flask API Server
Serves the frontend and /api/analyze endpoint.
"""

from flask import Flask, render_template, request, jsonify
from analyzer import VibeCodingAnalyzer

app = Flask(__name__)
analyzer = VibeCodingAnalyzer()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please provide a URL to analyze."}), 400

    result = analyzer.analyze(url)

    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
