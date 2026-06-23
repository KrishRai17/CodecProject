import re
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import bleach
from flask import Blueprint, request, jsonify, current_app
from db import users_col
from utils.logger import log_activity

auth_bp = Blueprint('auth', __name__)

# RFC 5322 standard email regex pattern
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

# Password complexity regex: minimum 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special character
PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$'

def _create_token(user_id_str: str) -> str:
    """Generate a JWT token for the user, expiring in 7 days."""
    payload = {
        'user_id': user_id_str,
        'exp': datetime.now(timezone.utc) + timedelta(days=7),
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm=current_app.config.get('JWT_ALGORITHM', 'HS256')
    )



@auth_bp.post('/api/auth/register')
def register():
    data = request.get_json() or {}
    name = data.get('name', '')
    email = data.get('email', '')
    password = data.get('password', '')

    # Basic validations
    if not name or not email or not password:
        log_activity(None, email or None, "REGISTER_FAILURE", "failure", {"reason": "Missing fields"})
        return jsonify({'ok': False, 'message': 'Name, email, and password are required.'}), 400

    # Sanitize inputs to prevent XSS and clean whitespace
    sanitized_name = bleach.clean(name.strip())
    sanitized_email = bleach.clean(email.strip().lower())

    if len(sanitized_name) < 2 or len(sanitized_name) > 80:
        log_activity(None, sanitized_email, "REGISTER_FAILURE", "failure", {"reason": "Name length violation"})
        return jsonify({'ok': False, 'message': 'Name must be between 2 and 80 characters.'}), 400

    if not re.match(EMAIL_REGEX, sanitized_email):
        log_activity(None, sanitized_email, "REGISTER_FAILURE", "failure", {"reason": "Invalid email format"})
        return jsonify({'ok': False, 'message': 'A valid email address is required.'}), 400

    if len(password) < 8 or len(password) > 128:
        log_activity(None, sanitized_email, "REGISTER_FAILURE", "failure", {"reason": "Password length violation"})
        return jsonify({'ok': False, 'message': 'Password must be between 8 and 128 characters.'}), 400

    if not re.match(PASSWORD_REGEX, password):
        log_activity(None, sanitized_email, "REGISTER_FAILURE", "failure", {"reason": "Weak password"})
        return jsonify({
            'ok': False,
            'message': 'Password must contain at least 8 characters, including 1 uppercase, 1 lowercase, 1 number, and 1 special character.'
        }), 400

    # Prevent NoSQL injection by ensuring input is strictly query-formatted
    try:
        existing_user = users_col.find_one({"email": sanitized_email})
        if existing_user:
            log_activity(None, sanitized_email, "REGISTER_FAILURE", "failure", {"reason": "User already exists"})
            return jsonify({'ok': False, 'message': 'A user with this email already exists.'}), 409

        # Secure password hashing with bcrypt
        salt = bcrypt.gensalt(rounds=12)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        # Insert user into database
        new_user = {
            "name": sanitized_name,
            "email": sanitized_email,
            "password_hash": hashed_password,
            "role": "user",
            "created_at": datetime.now(timezone.utc)
        }
        result = users_col.insert_one(new_user)
        user_id_str = str(result.inserted_id)

        # Generate access token
        token = _create_token(user_id_str)

        log_activity(result.inserted_id, sanitized_email, "REGISTER_SUCCESS", "success")

        return jsonify({
            'ok': True,
            'message': 'Registration successful.',
            'token': token,
            'user': {
                'name': sanitized_name,
                'email': sanitized_email
            }
        }), 201

    except Exception as e:
        log_activity(None, sanitized_email, "REGISTER_FAILURE", "failure", {"reason": "Internal database error", "error": str(e)})
        return jsonify({'ok': False, 'message': 'Internal server error occurred.'}), 500

@auth_bp.post('/api/auth/login')
def login():
    data = request.get_json() or {}
    email = data.get('email', '')
    password = data.get('password', '')

    if not email or not password:
        log_activity(None, email or None, "LOGIN_FAILURE", "failure", {"reason": "Missing credentials"})
        return jsonify({'ok': False, 'message': 'Email and password are required.'}), 400

    sanitized_email = bleach.clean(email.strip().lower())

    try:
        user = users_col.find_one({"email": sanitized_email})
        if not user:
            log_activity(None, sanitized_email, "LOGIN_FAILURE", "failure", {"reason": "User not found"})
            return jsonify({'ok': False, 'message': 'Invalid email or password.'}), 401

        # Check password hash validity
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            log_activity(user['_id'], sanitized_email, "LOGIN_FAILURE", "failure", {"reason": "Incorrect password"})
            return jsonify({'ok': False, 'message': 'Invalid email or password.'}), 401

        # Generate authentication token
        user_id_str = str(user['_id'])
        token = _create_token(user_id_str)

        log_activity(user['_id'], sanitized_email, "LOGIN_SUCCESS", "success")

        return jsonify({
            'ok': True,
            'message': 'Login successful.',
            'token': token,
            'user': {
                'name': user['name'],
                'email': user['email']
            }
        }), 200

    except Exception as e:
        log_activity(None, sanitized_email, "LOGIN_FAILURE", "failure", {"reason": "Internal server error during login", "error": str(e)})
        return jsonify({'ok': False, 'message': 'Internal server error occurred.'}), 500
