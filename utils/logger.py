from datetime import datetime, timezone
from flask import request
from db import logs_col

def log_activity(user_id, email, action, status, details=None):
    """
    Record an activity audit log in the MongoDB 'logs' collection.

    Args:
        user_id (ObjectId, str or None): The ID of the authenticated user, or None if unknown/unauthenticated.
        email (str or None): The email related to the action (e.g., login attempt).
        action (str): The event name (e.g., 'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'NOTE_CREATE', etc.).
        status (str): The result of the action (typically 'success' or 'failure').
        details (dict, optional): Extra context or metadata about the event.
    """
    ip_address = None
    try:
        # Check if we are within a Flask request context
        if request:
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ip_address and ',' in ip_address:
                ip_address = ip_address.split(',')[0].strip()
    except Exception:
        pass

    log_document = {
        "user_id": user_id,
        "email": email,
        "action": action,
        "status": status,
        "ip_address": ip_address,
        "timestamp": datetime.now(timezone.utc),
        "details": details or {}
    }

    try:
        logs_col.insert_one(log_document)
    except Exception as e:
        import sys
        print(f"FAILED TO WRITE ACTIVITY LOG: {e}", file=sys.stderr)
