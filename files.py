import os
import uuid
import base64
import io
from datetime import datetime, timezone
import bleach
from flask import Blueprint, request, jsonify, current_app, send_file
from bson.objectid import ObjectId
from bson.errors import InvalidId
from db import files_col
from middleware import token_required
from utils.encryption import encrypt_bytes, decrypt_bytes
from utils.logger import log_activity

files_bp = Blueprint('files', __name__)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt'}
ALLOWED_MIMETYPES = {
    'application/pdf',
    'image/png',
    'image/jpeg',
    'image/jpg',
    'image/gif',
    'text/plain'
}

# 5 MB upload size limit
MAX_FILE_SIZE = 5 * 1024 * 1024

def allowed_file(filename, content_type):
    """Verify file extension and content type match allowed list."""
    has_valid_ext = '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    has_valid_mime = content_type.lower() in ALLOWED_MIMETYPES
    return has_valid_ext and has_valid_mime

@files_bp.post('/api/files/upload')
@token_required
def upload_file(current_user):
    """
    Upload and encrypt a file. Stores encrypted payload on disk and metadata in MongoDB.
    """
    if 'file' not in request.files:
        log_activity(current_user['_id'], current_user['email'], "FILE_UPLOAD", "failure", {"reason": "No file part in request"})
        return jsonify({'ok': False, 'message': 'No file part in request.'}), 400

    file = request.files['file']
    if file.filename == '':
        log_activity(current_user['_id'], current_user['email'], "FILE_UPLOAD", "failure", {"reason": "Empty filename"})
        return jsonify({'ok': False, 'message': 'No file selected.'}), 400

    original_filename = bleach.clean(file.filename)
    content_type = file.content_type or 'application/octet-stream'

    if not allowed_file(original_filename, content_type):
        log_activity(current_user['_id'], current_user['email'], "FILE_UPLOAD", "failure", {
            "reason": "Forbidden file type", 
            "filename": original_filename,
            "mime_type": content_type
        })
        return jsonify({
            'ok': False, 
            'message': 'File type not allowed. Supported formats: PDF, PNG, JPG, JPEG, GIF, TXT.'
        }), 400

    # Ensure uploads directory exists
    upload_dir = os.path.join(current_app.root_path, 'uploads')
    os.makedirs(upload_dir, exist_ok=True)

    try:
        # Read file contents and check size limit
        file_bytes = file.read()
        file_size = len(file_bytes)
        if file_size > MAX_FILE_SIZE:
            log_activity(current_user['_id'], current_user['email'], "FILE_UPLOAD", "failure", {
                "reason": "File size exceeds limit", 
                "size": file_size
            })
            return jsonify({'ok': False, 'message': 'File size exceeds limit (Max 5MB).'}), 413

        # Encrypt the binary file payload
        encryption_key = current_app.config['ENCRYPTION_KEY']
        encrypted_data, nonce = encrypt_bytes(file_bytes, encryption_key)

        # Generate unique name on disk to prevent path injection / overwriting
        disk_filename = uuid.uuid4().hex
        disk_path = os.path.join(upload_dir, disk_filename)

        # Write encrypted bytes directly to disk
        with open(disk_path, 'wb') as f:
            f.write(encrypted_data)

        # Save metadata document in MongoDB
        file_metadata = {
            "user_id": current_user['_id'],
            "original_filename": original_filename,
            "disk_filename": disk_filename,
            "file_path": disk_path,
            "mime_type": content_type,
            "file_size": file_size,
            "nonce_b64": base64.urlsafe_b64encode(nonce).decode('utf-8'),
            "created_at": datetime.now(timezone.utc)
        }

        result = files_col.insert_one(file_metadata)
        file_id_str = str(result.inserted_id)

        log_activity(current_user['_id'], current_user['email'], "FILE_UPLOAD", "success", {
            "file_id": file_id_str,
            "filename": original_filename
        })

        return jsonify({
            'ok': True,
            'message': 'File uploaded and encrypted successfully.',
            'file': {
                'id': file_id_str,
                'filename': original_filename,
                'size': file_size,
                'mime_type': content_type
            }
        }), 201

    except Exception as e:
        log_activity(current_user['_id'], current_user['email'], "FILE_UPLOAD", "failure", {
            "reason": "Internal upload failure", 
            "error": str(e)
        })
        return jsonify({'ok': False, 'message': 'Failed to upload file.'}), 500

@files_bp.get('/api/files')
@token_required
def list_files(current_user):
    """List metadata for all files owned by the current user."""
    try:
        cursor = files_col.find({"user_id": current_user['_id']}).sort("created_at", -1)
        files_list = []
        for doc in cursor:
            files_list.append({
                'id': str(doc['_id']),
                'filename': doc['original_filename'],
                'mime_type': doc['mime_type'],
                'size': doc['file_size'],
                'created_at': doc['created_at'].isoformat()
            })
        return jsonify({'ok': True, 'files': files_list}), 200
    except Exception as e:
        return jsonify({'ok': False, 'message': f'Failed to list files: {str(e)}'}), 500

@files_bp.get('/api/files/download/<file_id>')
@token_required
def download_file(current_user, file_id):
    """
    Authorized file download. Fetches encrypted file from disk, decrypts in memory,
    and streams to the client.
    """
    try:
        file_oid = ObjectId(file_id)
    except InvalidId:
        log_activity(current_user['_id'], current_user['email'], "FILE_DOWNLOAD", "failure", {
            "reason": "Invalid ObjectId format", 
            "file_id": file_id
        })
        return jsonify({'ok': False, 'message': 'Invalid file ID.'}), 400

    try:
        # Find file metadata and check ownership
        file_doc = files_col.find_one({"_id": file_oid, "user_id": current_user['_id']})
        if not file_doc:
            log_activity(current_user['_id'], current_user['email'], "FILE_DOWNLOAD", "failure", {
                "reason": "File not found or unauthorized", 
                "file_id": file_id
            })
            return jsonify({'ok': False, 'message': 'File not found or access denied.'}), 404

        disk_path = file_doc['file_path']
        if not os.path.exists(disk_path):
            log_activity(current_user['_id'], current_user['email'], "FILE_DOWNLOAD", "failure", {
                "reason": "File missing on disk", 
                "file_id": file_id,
                "disk_path": disk_path
            })
            return jsonify({'ok': False, 'message': 'File payload is missing on disk.'}), 500

        # Read encrypted bytes
        with open(disk_path, 'rb') as f:
            encrypted_bytes = f.read()

        # Decrypt in memory
        encryption_key = current_app.config['ENCRYPTION_KEY']
        nonce = base64.urlsafe_b64decode(file_doc['nonce_b64'].encode('utf-8'))
        decrypted_bytes = decrypt_bytes(encrypted_bytes, nonce, encryption_key)

        log_activity(current_user['_id'], current_user['email'], "FILE_DOWNLOAD", "success", {
            "file_id": file_id,
            "filename": file_doc['original_filename']
        })

        # Send decrypted bytes stream as file download
        return send_file(
            io.BytesIO(decrypted_bytes),
            mimetype=file_doc['mime_type'],
            as_attachment=True,
            download_name=file_doc['original_filename']
        )

    except Exception as e:
        log_activity(current_user['_id'], current_user['email'], "FILE_DOWNLOAD", "failure", {
            "reason": "Decryption/stream failure", 
            "file_id": file_id,
            "error": str(e)
        })
        return jsonify({'ok': False, 'message': 'Failed to process file download.'}), 500

@files_bp.delete('/api/files/<file_id>')
@token_required
def delete_file(current_user, file_id):
    """
    Delete a file. Deletes the encrypted payload from disk and metadata from MongoDB.
    """
    try:
        file_oid = ObjectId(file_id)
    except InvalidId:
        log_activity(current_user['_id'], current_user['email'], "FILE_DELETE", "failure", {
            "reason": "Invalid ObjectId format", 
            "file_id": file_id
        })
        return jsonify({'ok': False, 'message': 'Invalid file ID.'}), 400

    try:
        # Check metadata and ownership
        file_doc = files_col.find_one({"_id": file_oid, "user_id": current_user['_id']})
        if not file_doc:
            log_activity(current_user['_id'], current_user['email'], "FILE_DELETE", "failure", {
                "reason": "File not found or unauthorized", 
                "file_id": file_id
            })
            return jsonify({'ok': False, 'message': 'File not found or access denied.'}), 404

        # Delete from disk
        disk_path = file_doc['file_path']
        if os.path.exists(disk_path):
            os.remove(disk_path)

        # Delete metadata from DB
        files_col.delete_one({"_id": file_oid})

        log_activity(current_user['_id'], current_user['email'], "FILE_DELETE", "success", {
            "file_id": file_id,
            "filename": file_doc['original_filename']
        })

        return jsonify({'ok': True, 'message': 'File deleted successfully.'}), 200

    except Exception as e:
        log_activity(current_user['_id'], current_user['email'], "FILE_DELETE", "failure", {
            "reason": "Database/Disk deletion failure", 
            "file_id": file_id,
            "error": str(e)
        })
        return jsonify({'ok': False, 'message': 'Failed to delete file.'}), 500
