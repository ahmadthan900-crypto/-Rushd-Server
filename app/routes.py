import os
from flask import Blueprint, request, jsonify, current_app
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash
from .db import get_db
from .security import normalize_phone, validate_registration, hash_password, verify_password

api = Blueprint("api", __name__)
TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7

def issue_token(subject, role):
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="rushd-auth-v1")
    return serializer.dumps({"sub": str(subject), "role": role})

def read_token(token):
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="rushd-auth-v1")
    try:
        return serializer.loads(token, max_age=TOKEN_TTL_SECONDS)
    except (BadSignature, SignatureExpired):
        return None

@api.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    phone = normalize_phone(data.get("phone"))
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    error = validate_registration(phone, username, password)
    if error:
        return jsonify({"ok": False, "message": error}), 400
    try:
        with get_db() as conn:
            row = conn.execute(
                "INSERT INTO users(phone, username, password_hash) VALUES (%s,%s,%s) RETURNING id",
                (phone, username, hash_password(password))
            ).fetchone()
        return jsonify({"ok": True, "message": "تم إنشاء الحساب بنجاح.", "user_id": row["id"]}), 201
    except Exception as exc:
        current_app.logger.exception("Registration failed")
        msg = str(exc).lower()
        if "unique" in msg:
            return jsonify({"ok": False, "message": "رقم الهاتف أو اسم المستخدم مستخدم مسبقاً."}), 409
        return jsonify({"ok": False, "message": "تعذر إنشاء الحساب حالياً."}), 500

@api.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    phone = normalize_phone(data.get("phone"))
    password = str(data.get("password") or "")
    with get_db() as conn:
        user = conn.execute(
            "SELECT id, phone, username, password_hash FROM users WHERE phone=%s AND is_active=TRUE",
            (phone,)
        ).fetchone()
    if not user or not verify_password(user["password_hash"], password):
        return jsonify({"ok": False, "message": "رقم الهاتف أو كلمة المرور غير صحيحة."}), 401
    return jsonify({
        "ok": True, "message": "تم تسجيل الدخول بنجاح.",
        "token": issue_token(user["id"], "user"),
        "user": {"id": user["id"], "phone": user["phone"], "username": user["username"], "role": "user"}
    })

@api.post("/admin/login")
def admin_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or "")
    password = str(data.get("password") or "")
    expected_username = os.environ.get("ADMIN_USERNAME", "")
    expected_password = os.environ.get("ADMIN_PASSWORD", "")
    if not expected_username or not expected_password:
        return jsonify({"ok": False, "message": "إعدادات المدير غير مكتملة في الاستضافة."}), 503

    # First login provisions the admin record using a secure password hash.
    with get_db() as conn:
        admin = conn.execute("SELECT id, password_hash FROM admins WHERE username=%s", (expected_username,)).fetchone()
        if admin is None:
            admin_id = conn.execute(
                "INSERT INTO admins(username,password_hash) VALUES (%s,%s) RETURNING id",
                (expected_username, generate_password_hash(expected_password, method="scrypt"))
            ).fetchone()["id"]
            admin = {"id": admin_id, "password_hash": generate_password_hash(expected_password, method="scrypt")}
        if username != expected_username or not verify_password(admin["password_hash"], password):
            return jsonify({"ok": False, "message": "اسم المدير أو كلمة المرور غير صحيحة."}), 401
        conn.execute("INSERT INTO admin_audit(admin_id,action) VALUES (%s,%s)", (admin["id"], "login"))
    return jsonify({
        "ok": True, "message": "تم تسجيل دخول المدير.",
        "token": issue_token(admin["id"], "admin"),
        "user": {"id": admin["id"], "username": expected_username, "role": "admin"}
    })

@api.get("/me")
def me():
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    payload = read_token(token)
    if not payload:
        return jsonify({"ok": False, "message": "رمز الدخول غير صالح أو منتهي."}), 401
    return jsonify({"ok": True, "subject": payload["sub"], "role": payload["role"]})
