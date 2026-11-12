import re
from werkzeug.security import generate_password_hash, check_password_hash

def normalize_phone(phone):
    # Remove spaces only; the Syrian mobile format is 09 followed by 8 digits.
    return re.sub(r"\s+", "", str(phone or ""))

def validate_registration(phone, username, password):
    phone = normalize_phone(phone)
    username = str(username or "").strip()
    password = str(password or "")
    if not re.fullmatch(r"09\d{8}", phone):
        return "رقم الهاتف يجب أن يبدأ بـ 09 ويتكون من 10 أرقام."
    if not username:
        return "اسم المستخدم مطلوب."
    if len(username) >= 15:
        return "اسم المستخدم يجب أن يكون أقل من 15 حرفاً."
    if len(password) < 10:
        return "كلمة المرور يجب ألا تقل عن 10 أحرف."
    return None

def hash_password(password):
    return generate_password_hash(password, method="scrypt")

def verify_password(password_hash, password):
    return check_password_hash(password_hash, password)
