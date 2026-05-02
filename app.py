"""
VibeCheck — Flask API Server
Serves the frontend and /api/analyze endpoint.
"""

import logging
import os

from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from analyzer import VibeCodingAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = Flask(__name__)
# A URL plus tiny JSON envelope is at most a few hundred bytes; cap at 16 KB to
# reject pathological bodies without affecting any real client.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

# Rate limiting. Default storage is in-memory, which is correct for a single
# process and degrades gracefully on serverless (per-instance counters).
# Set RATELIMIT_STORAGE_URI=redis://... in env to share counters across instances.
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["120 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    strategy="fixed-window",
)

analyzer = VibeCodingAnalyzer()


@app.errorhandler(429)
def ratelimit_handler(_exc):
    return jsonify({
        "error": "Rate limit exceeded. Please slow down and try again in a minute.",
    }), 429


@app.route("/")
@limiter.exempt
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
@limiter.limit("10 per minute; 60 per hour")
def analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Please provide a URL to analyze."}), 400

    result = analyzer.analyze(url)

    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)


if __name__ == "__main__":
    app.run(port=5000)
