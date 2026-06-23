import os
import uuid
import base64
from datetime import datetime, timezone
import bcrypt
import bleach

from flask import render_template, request, redirect, url_for, session, flash, current_app
from bson.objectid import ObjectId
from functools import wraps

from db import users_col, notes_col, files_col, logs_col
from utils.encryption import encrypt_string, encrypt_bytes, decrypt_string


# ================= LOGIN REQUIRED =================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))

        user = users_col.find_one({"_id": ObjectId(session['user_id'])})
        if not user:
            session.clear()
            return redirect(url_for('login_page'))

        return f(user, *args, **kwargs)
    return wrapper


# ================= ROUTES =================
def init_web_routes(app):

    # HOME
    @app.get('/')
    def home():
        return render_template('index.html')

    @app.get('/how-it-works')
    def how_it_works():
        return render_template('how_it_works.html')

    # ================= AUTH =================
    @app.get('/login')
    def login_page():
        return render_template('login.html')

    @app.get('/register')
    def register_page():
        return render_template('register.html')

    @app.post('/register')
    def register_submit():
        email = bleach.clean(request.form.get('email').lower())
        password = request.form.get('password')

        if users_col.find_one({"email": email}):
            flash("User already exists")
            return redirect(url_for('register_page'))

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        user = {
            "email": email,
            "password_hash": hashed,
            "role": "user",
            "created_at": datetime.now(timezone.utc)
        }

        res = users_col.insert_one(user)
        session['user_id'] = str(res.inserted_id)

        return redirect(url_for('vault'))

    # 🔥 MAIN LOGIN FIX (ADMIN REDIRECT)
    @app.post('/login')
    def login_submit():
        email = request.form.get('email').lower()
        password = request.form.get('password')

        user = users_col.find_one({"email": email})

        if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            flash("Invalid login")
            return redirect(url_for('login_page'))

        session['user_id'] = str(user['_id'])

        # ✅ ADMIN
        if user.get("role") == "admin":
            return redirect(url_for('admin_dashboard'))

        # ✅ NORMAL USER
        return redirect(url_for('vault'))

    @app.post('/logout')
    def logout():
        session.clear()
        return redirect(url_for('home'))

    # ================= VAULT =================
    @app.get('/vault')
    @login_required
    def vault(user):
        key = current_app.config['ENCRYPTION_KEY']

        notes = []
        for doc in notes_col.find({"user_id": user['_id']}):
            try:
                title = decrypt_string(doc['title_cipher'], doc['title_nonce'], key)
                content = decrypt_string(doc['content_cipher'], doc['content_nonce'], key)

                notes.append({
                    "id": str(doc['_id']),
                    "title": title,
                    "content": content,
                    "created_at": doc['created_at']
                })
            except:
                notes.append({
                    "id": str(doc['_id']),
                    "title": "Error",
                    "content": "Decryption failed",
                    "created_at": doc['created_at']
                })

        files = list(files_col.find({"user_id": user['_id']}))

        return render_template('vault.html', user=user, notes=notes, files=files)

    @app.post('/create-note')
    @login_required
    def web_create_note(user):
        title = request.form.get('title')
        content = request.form.get('content')

        key = current_app.config['ENCRYPTION_KEY']
        t_cipher, t_nonce = encrypt_string(title, key)
        c_cipher, c_nonce = encrypt_string(content, key)

        notes_col.insert_one({
            "user_id": user['_id'],
            "title_cipher": t_cipher,
            "title_nonce": t_nonce,
            "content_cipher": c_cipher,
            "content_nonce": c_nonce,
            "created_at": datetime.now(timezone.utc)
        })

        return redirect(url_for('vault'))

    @app.post('/delete-note/<note_id>')
    @login_required
    def web_delete_note(user, note_id):
        notes_col.delete_one({
            "_id": ObjectId(note_id),
            "user_id": user['_id']
        })
        return redirect(url_for('vault'))

    @app.post('/upload-file')
    @login_required
    def web_upload_file(user):
        file = request.files.get('file')
        data = file.read()

        key = current_app.config['ENCRYPTION_KEY']
        encrypted, nonce = encrypt_bytes(data, key)

        fname = uuid.uuid4().hex
        path = os.path.join("uploads", fname)

        os.makedirs("uploads", exist_ok=True)

        with open(path, "wb") as f:
            f.write(encrypted)

        files_col.insert_one({
            "user_id": user['_id'],
            "original_filename": file.filename,
            "file_path": path,
            "nonce": base64.b64encode(nonce).decode(),
            "created_at": datetime.now(timezone.utc)
        })

        return redirect(url_for('vault'))

    # ================= ADMIN DASHBOARD =================
    @app.get('/admin-dashboard')
    @login_required
    def admin_dashboard(user):

        if user.get("role") != "admin":
            return "Access Denied"

        logs = list(logs_col.find().sort("timestamp", -1))

        stats = {
            "total_users": users_col.count_documents({}),
            "total_logs": logs_col.count_documents({}),
            "failed_logins": logs_col.count_documents({"action": "LOGIN_FAILURE"})
        }

        return render_template('admin_dashboard.html', logs=logs, stats=stats)