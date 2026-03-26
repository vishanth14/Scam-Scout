import logging
import os
import sys
from typing import Any, Dict

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from analysis import JobAnalyzer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    CORS(app)
    
    analyzer = JobAnalyzer()

    @app.get("/api/health")
    def health() -> Any:
        return jsonify({"ok": True})

    @app.post("/api/analyze")
    def analyze() -> Any:
        payload: Dict[str, Any] = request.get_json(silent=True) or {}
        job_text = payload.get("job_text", "")
        job_url = payload.get("job_url", None)

        if not (isinstance(job_text, str) and job_text.strip()) and not (isinstance(job_url, str) and job_url.strip()):
            return jsonify({"error": "Provide either 'job_text' or 'job_url'"}), 400

        result = analyzer.analyze(
            job_text=job_text if isinstance(job_text, str) else "",
            job_url=job_url if isinstance(job_url, str) and job_url.strip() else None,
        )
        return jsonify(result)

    @app.get("/")
    def index() -> Any:
        return render_template("index.html")

    return app


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    host = os.getenv("HOST", "127.0.0.1")
    app = create_app()
    logger.info(f"Server starting on {host}:{port}")
    app.run(host=host, port=port, debug=True)