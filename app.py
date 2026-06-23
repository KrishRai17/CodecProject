import os
from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from dotenv import load_dotenv

from auth import auth_bp
from notes import notes_bp
from files import files_bp
from views import init_web_routes
from middleware import token_required, admin_required

load_dotenv()

app = Flask(__name__)

# Config
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET', 'jwt-secret')
app.config['ENCRYPTION_KEY'] = os.getenv('ENCRYPTION_KEY', 'your-32-byte-key')
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# Security
limiter = Limiter(key_func=get_remote_address, app=app)
csrf = CSRFProtect(app)

# Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(notes_bp)
app.register_blueprint(files_bp)

csrf.exempt(auth_bp)
csrf.exempt(notes_bp)
csrf.exempt(files_bp)

# Web routes
init_web_routes(app)

# ================= ADMIN APIs =================

@app.get('/api/admin/logs')
@token_required
@admin_required
def get_logs(user):
    from db import logs_col
    from bson import ObjectId

    logs = []
    for log in logs_col.find().sort("timestamp", -1):
        log["_id"] = str(log["_id"])
        logs.append(log)

    return {"ok": True, "logs": logs}


@app.get('/api/admin/stats')
@token_required
@admin_required
def admin_stats(user):
    from db import users_col, logs_col

    return {
        "ok": True,
        "stats": {
            "total_users": users_col.count_documents({}),
            "total_logs": logs_col.count_documents({}),
            "failed_logins": logs_col.count_documents({"action": "LOGIN_FAILURE"})
        }
    }


@app.get('/api/user/me')
@token_required
def get_profile(user):
    return {
        "ok": True,
        "user": {
            "email": user.get("email"),
            "role": user.get("role")
        }
    }


# ================= ERRORS =================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'ok': False, 'message': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'ok': False, 'message': 'Server error'}), 500


# ================= RUN =================

if __name__ == '__main__':
    app.run(debug=True)