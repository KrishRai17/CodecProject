import os
import unittest
import io
from bson.objectid import ObjectId
from app import app
from db import users_col, notes_col, files_col, logs_col

class SecureVaultAPITestCase(unittest.TestCase):
    def setUp(self):
        # Configure app for testing mode (disables some strict production features if needed)
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Test credentials and user details
        self.test_email = "testuser_unique_vault_99@example.com"
        self.test_password = "SecurePassword123!"
        self.test_name = "Auth Test User"
        
        # Ensure database is clean of this test account before running test
        self.cleanup()

    def tearDown(self):
        # Clean up database records after tests run
        self.cleanup()

    def cleanup(self):
        # Retrieve test user to remove related records
        user = users_col.find_one({"email": self.test_email})
        if user:
            # 1. Clean up files on disk associated with this user
            cursor = files_col.find({"user_id": user["_id"]})
            for file_doc in cursor:
                path = file_doc.get("file_path")
                if path and os.path.exists(path):
                    try:
                        os.remove(path)
                    except Exception:
                        pass
            
            # 2. Delete entries across collections
            files_col.delete_many({"user_id": user["_id"]})
            notes_col.delete_many({"user_id": user["_id"]})
            logs_col.delete_many({"user_id": user["_id"]})
            users_col.delete_one({"_id": user["_id"]})
            
        # Clean up any residual logs for this email
        logs_col.delete_many({"email": self.test_email})

    def test_01_register_validation(self):
        """Test user registration with valid and invalid details."""
        # 1. Test missing fields
        resp = self.client.post('/api/auth/register', json={"email": self.test_email})
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json()['ok'])

        # 2. Test weak password (fails complexity check)
        resp = self.client.post('/api/auth/register', json={
            "name": self.test_name,
            "email": self.test_email,
            "password": "weakpassword"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json()['ok'])
        self.assertIn("Password must contain", resp.get_json()['message'])

        # 3. Successful registration
        resp = self.client.post('/api/auth/register', json={
            "name": self.test_name,
            "email": self.test_email,
            "password": self.test_password
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data['ok'])
        self.assertIn('token', data)

        # 4. Verify log entry was created
        log = logs_col.find_one({"email": self.test_email, "action": "REGISTER_SUCCESS"})
        self.assertIsNotNone(log)
        self.assertEqual(log['status'], 'success')

    def test_02_login_flow(self):
        """Test login authentication and JWT token generation."""
        # Pre-register test user
        self.client.post('/api/auth/register', json={
            "name": self.test_name,
            "email": self.test_email,
            "password": self.test_password
        })

        # 1. Invalid credentials login
        resp = self.client.post('/api/auth/login', json={
            "email": self.test_email,
            "password": "wrong_password"
        })
        self.assertEqual(resp.status_code, 401)
        self.assertFalse(resp.get_json()['ok'])
        
        # Verify log entry for failure
        failure_log = logs_col.find_one({"email": self.test_email, "action": "LOGIN_FAILURE"})
        self.assertIsNotNone(failure_log)
        self.assertEqual(failure_log['status'], 'failure')

        # 2. Valid credentials login
        resp = self.client.post('/api/auth/login', json={
            "email": self.test_email,
            "password": self.test_password
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['ok'])
        self.assertIn('token', data)

        # Verify log entry for success
        success_log = logs_col.find_one({"email": self.test_email, "action": "LOGIN_SUCCESS"})
        self.assertIsNotNone(success_log)
        self.assertEqual(success_log['status'], 'success')

    def test_03_notes_security_and_crud(self):
        """Test note creation (encryption), note viewing (decryption), and deletion."""
        # Register and login to obtain valid JWT token
        reg_resp = self.client.post('/api/auth/register', json={
            "name": self.test_name,
            "email": self.test_email,
            "password": self.test_password
        })
        token = reg_resp.get_json()['token']
        headers = {'Authorization': f'Bearer {token}'}

        # 1. Test CRUD: Create note
        note_title = "Vault Access Credentials"
        note_content = "Master secret key: antigravity_is_awesome_2026!"
        
        create_resp = self.client.post('/api/notes', headers=headers, json={
            "title": note_title,
            "content": note_content
        })
        self.assertEqual(create_resp.status_code, 201)
        note_id = create_resp.get_json()['note']['id']

        # 2. Security Check: Verify that data is encrypted in the raw MongoDB database
        raw_db_note = notes_col.find_one({"_id": ObjectId(note_id)})
        self.assertIsNotNone(raw_db_note)
        # Ensure plaintext title and content are NEVER stored in database
        self.assertNotEqual(raw_db_note['title_cipher'], note_title)
        self.assertNotEqual(raw_db_note['content_cipher'], note_content)
        self.assertIn('title_nonce', raw_db_note)
        self.assertIn('content_nonce', raw_db_note)

        # 3. Test CRUD: Read notes (should decrypt in-flight and return plaintext)
        list_resp = self.client.get('/api/notes', headers=headers)
        self.assertEqual(list_resp.status_code, 200)
        notes = list_resp.get_json()['notes']
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]['title'], note_title)
        self.assertEqual(notes[0]['content'], note_content)

        # 4. Test CRUD: Delete note
        delete_resp = self.client.delete(f'/api/notes/{note_id}', headers=headers)
        self.assertEqual(delete_resp.status_code, 200)
        self.assertTrue(delete_resp.get_json()['ok'])

        # Verify deletion from database
        self.assertIsNone(notes_col.find_one({"_id": ObjectId(note_id)}))

    def test_04_files_security_and_crud(self):
        """Test secure file upload (encryption on disk) and download (decryption in memory)."""
        # Register and login to obtain valid JWT token
        reg_resp = self.client.post('/api/auth/register', json={
            "name": self.test_name,
            "email": self.test_email,
            "password": self.test_password
        })
        token = reg_resp.get_json()['token']
        headers = {'Authorization': f'Bearer {token}'}

        # 1. Test CRUD: Upload file
        filename = "confidential.txt"
        file_data = b"This file contains confidential security keys and parameters."
        
        multipart_data = {
            'file': (io.BytesIO(file_data), filename)
        }
        
        upload_resp = self.client.post(
            '/api/files/upload',
            headers=headers,
            data=multipart_data,
            content_type='multipart/form-data'
        )
        self.assertEqual(upload_resp.status_code, 201)
        file_id = upload_resp.get_json()['file']['id']

        # 2. Security Check: Verify encrypted payload is stored on disk
        metadata = files_col.find_one({"_id": ObjectId(file_id)})
        self.assertIsNotNone(metadata)
        disk_path = metadata['file_path']
        self.assertTrue(os.path.exists(disk_path))
        
        # Read the file bytes directly from the local disk
        with open(disk_path, 'rb') as f:
            disk_bytes = f.read()

        # The data written to disk must be fully encrypted, not equal to the original plaintext
        self.assertNotEqual(disk_bytes, file_data)

        # 3. Test CRUD: Download file (verifying in-memory decryption and headers)
        download_resp = self.client.get(f'/api/files/download/{file_id}', headers=headers)
        self.assertEqual(download_resp.status_code, 200)
        self.assertEqual(download_resp.data, file_data) # Decrypted data matches original input
        self.assertTrue(download_resp.headers['Content-Type'].startswith('text/plain'))
        self.assertIn(f'filename={filename}', download_resp.headers['Content-Disposition'])

        # 4. Test CRUD: Delete file
        delete_resp = self.client.delete(f'/api/files/{file_id}', headers=headers)
        self.assertEqual(delete_resp.status_code, 200)
        
        # Verify file is deleted from physical storage disk
        self.assertFalse(os.path.exists(disk_path))
        # Verify metadata is deleted from database
        self.assertIsNone(files_col.find_one({"_id": ObjectId(file_id)}))

if __name__ == '__main__':
    unittest.main()
