from functools import wraps
import jwt
from flask import request, jsonify, current_app
from bson.objectid import ObjectId
from db import users_col
from functools import wraps
from flask import jsonify

def admin_required(f):
    @wraps(f)
    def decorated(user, *args, **kwargs):
        if user.get("role") != "admin":
            return jsonify({
                "ok": False,
                "message": "Admin access required"
            }), 403
        return f(user, *args, **kwargs)
    return decorated

def token_required(f):
    """
    Decorator to protect routes requiring authentication.
    Extracts, validates, and decodes the JWT token from the Authorization header.
    Passes the authenticated user's MongoDB document to the decorated view function.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Extract JWT from Authorization Header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'ok': False, 'message': 'Token is missing. Access denied.'}), 401

        try:
            # Decode token using app's JWT configuration
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=[current_app.config.get('JWT_ALGORITHM', 'HS256')]
            )

            # Retrieve userId and find user in MongoDB
            user_id_str = payload.get('user_id')
            if not user_id_str:
                return jsonify({'ok': False, 'message': 'Token structure is invalid.'}), 401

            user = users_col.find_one({"_id": ObjectId(user_id_str)})
            if not user:
                return jsonify({'ok': False, 'message': 'Authenticated user not found.'}), 401

        except jwt.ExpiredSignatureError:
            return jsonify({'ok': False, 'message': 'Token has expired.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'ok': False, 'message': 'Invalid token.'}), 401
        except Exception as e:
            return jsonify({'ok': False, 'message': f'Authentication failed: {str(e)}'}), 401

        # Pass current_user to the route
        return f(user, *args, **kwargs)

    return decorated
