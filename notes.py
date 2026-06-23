from datetime import datetime, timezone
import bleach
from flask import Blueprint, request, jsonify, current_app
from bson.objectid import ObjectId
from bson.errors import InvalidId
from db import notes_col
from middleware import token_required
from utils.encryption import encrypt_string, decrypt_string
from utils.logger import log_activity

notes_bp = Blueprint('notes', __name__)

@notes_bp.post('/api/notes')
@token_required
def create_note(current_user):
    """
    Create a new note. Encrypts the title and content using AES-256-GCM before
    saving them to MongoDB.
    """
    data = request.get_json() or {}
    title = data.get('title', '')
    content = data.get('content', '')

    # Validation
    if not title or not content:
        log_activity(current_user['_id'], current_user['email'], "NOTE_CREATE", "failure", {"reason": "Missing title or content"})
        return jsonify({'ok': False, 'message': 'Title and content are required.'}), 400

    # Sanitize title and content to prevent XSS (Stored XSS protection)
    sanitized_title = bleach.clean(title.strip())
    sanitized_content = bleach.clean(content.strip())

    if len(sanitized_title) < 1 or len(sanitized_title) > 120:
        log_activity(current_user['_id'], current_user['email'], "NOTE_CREATE", "failure", {"reason": "Title length violation"})
        return jsonify({'ok': False, 'message': 'Title must be between 1 and 120 characters.'}), 400

    if len(sanitized_content) < 1 or len(sanitized_content) > 10000:
        log_activity(current_user['_id'], current_user['email'], "NOTE_CREATE", "failure", {"reason": "Content length violation"})
        return jsonify({'ok': False, 'message': 'Content must be between 1 and 10000 characters.'}), 400

    try:
        # Encrypt the title and content using the application's global ENCRYPTION_KEY
        encryption_key = current_app.config['ENCRYPTION_KEY']
        title_cipher, title_nonce = encrypt_string(sanitized_title, encryption_key)
        content_cipher, content_nonce = encrypt_string(sanitized_content, encryption_key)

        # Build note document linked to user
        note_doc = {
            "user_id": current_user['_id'],
            "title_cipher": title_cipher,
            "title_nonce": title_nonce,
            "content_cipher": content_cipher,
            "content_nonce": content_nonce,
            "created_at": datetime.now(timezone.utc)
        }

        result = notes_col.insert_one(note_doc)
        note_id_str = str(result.inserted_id)

        log_activity(current_user['_id'], current_user['email'], "NOTE_CREATE", "success", {"note_id": note_id_str})

        return jsonify({
            'ok': True,
            'message': 'Note created securely.',
            'note': {
                'id': note_id_str,
                'title': sanitized_title,
                'content': sanitized_content,
                'created_at': note_doc['created_at'].isoformat()
            }
        }), 201

    except Exception as e:
        log_activity(current_user['_id'], current_user['email'], "NOTE_CREATE", "failure", {"reason": "Encryption/Database failure", "error": str(e)})
        return jsonify({'ok': False, 'message': 'Failed to save note.'}), 500

@notes_bp.get('/api/notes')
@token_required
def get_notes(current_user):
    """
    Get all notes belonging to the authenticated user.
    Decrypts the notes before returning them.
    """
    try:
        encryption_key = current_app.config['ENCRYPTION_KEY']
        # Retrieve notes linked to this user's ID
        cursor = notes_col.find({"user_id": current_user['_id']}).sort("created_at", -1)
        
        decrypted_notes = []
        for note in cursor:
            try:
                decrypted_title = decrypt_string(note['title_cipher'], note['title_nonce'], encryption_key)
                decrypted_content = decrypt_string(note['content_cipher'], note['content_nonce'], encryption_key)
                
                decrypted_notes.append({
                    'id': str(note['_id']),
                    'title': decrypted_title,
                    'content': decrypted_content,
                    'created_at': note['created_at'].isoformat()
                })
            except Exception as decrypt_err:
                # If a specific note fails to decrypt (e.g. corruption/bad key), don't crash the whole list retrieval
                decrypted_notes.append({
                    'id': str(note['_id']),
                    'title': "[DECRYPTION FAILURE]",
                    'content': "[Failed to decrypt content securely]",
                    'created_at': note['created_at'].isoformat(),
                    'error': str(decrypt_err)
                })

        return jsonify({
            'ok': True,
            'notes': decrypted_notes
        }), 200

    except Exception as e:
        return jsonify({'ok': False, 'message': f'Failed to retrieve notes: {str(e)}'}), 500

@notes_bp.delete('/api/notes/<note_id>')
@token_required
def delete_note(current_user, note_id):
    """
    Delete a specific note. Ensures the note exists and belongs to the current user.
    """
    try:
        note_oid = ObjectId(note_id)
    except InvalidId:
        log_activity(current_user['_id'], current_user['email'], "NOTE_DELETE", "failure", {"reason": "Invalid ObjectId format", "note_id": note_id})
        return jsonify({'ok': False, 'message': 'Invalid note ID format.'}), 400

    try:
        # Query note matching both note _id and owner user_id
        note = notes_col.find_one({"_id": note_oid, "user_id": current_user['_id']})
        if not note:
            log_activity(current_user['_id'], current_user['email'], "NOTE_DELETE", "failure", {"reason": "Note not found or access denied", "note_id": note_id})
            return jsonify({'ok': False, 'message': 'Note not found or unauthorized.'}), 404

        # Perform deletion
        notes_col.delete_one({"_id": note_oid})
        
        log_activity(current_user['_id'], current_user['email'], "NOTE_DELETE", "success", {"note_id": note_id})
        return jsonify({
            'ok': True,
            'message': 'Note deleted successfully.'
        }), 200

    except Exception as e:
        log_activity(current_user['_id'], current_user['email'], "NOTE_DELETE", "failure", {"reason": "Database failure during deletion", "error": str(e), "note_id": note_id})
        return jsonify({'ok': False, 'message': 'Failed to delete note.'}), 500
