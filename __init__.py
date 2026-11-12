import os
from flask import Flask, jsonify
from .db import init_db
from .routes import api

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("RUSHD_SECRET_KEY")
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("RUSHD_SECRET_KEY is required. Set it in the hosting environment.")

    app.register_blueprint(api, url_prefix="/api")

    @app.get("/")
    def home():
        return jsonify({"app": "Rushd Server", "status": "running"})

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True, "service": "rushd-api"})

    init_db()
    return app
