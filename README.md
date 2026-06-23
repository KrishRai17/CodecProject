# Secure Vault Web Application

A complete, production-grade security-focused backend system built with **Flask (Python)** and **MongoDB**. This application demonstrates advanced security concepts including user authentication (bcrypt), authorization (JWT), envelope encryption (AES-256-GCM) for note storage, secure disk-encryption for file storage with in-memory decryption streaming, input sanitization (bleach), rate-limiting (Flask-Limiter), and a database audit logging system.

---

## 🛠️ Technology Stack & Dependencies

- **Core Framework**: Flask (Python 3)
- **Database**: MongoDB (`pymongo[srv]` for Atlas)
- **Authentication**: JWT (JSON Web Tokens) via `PyJWT`
- **Security Utilities**: Cryptography (`cryptography.hazmat`), Bcrypt password hashing (`bcrypt`), and HTML input sanitization (`bleach` for XSS protection)
- **Developer Resiliency**: `mongomock` in-memory database fallback

---

## 📂 Project Structure

```text
├── app.py                   # Main application entry point & security configs
├── auth.py                  # Authentication Blueprint (Register & Login APIs)
├── notes.py                 # Secure Notes Blueprint (Encrypted CRUD operations)
├── files.py                 # Encrypted File Storage Blueprint (Upload / Stream Download)
├── middleware.py            # Custom JWT auth token validation decorator
├── db.py                    # MongoDB Client initializer with mongomock fallback
├── requirements.txt         # Package dependencies list
├── postman_collection.json  # Pre-built Postman collection for API testing
├── utils/
│   ├── encryption.py        # AES-256-GCM Encryption / Decryption routines
│   └── logger.py            # MongoDB audit logger helper
└── tests/
    └── test_api.py          # Comprehensive integration test suite
```

---

## 🚀 Getting Started

Follow these steps to run the project locally on your machine:

### 1. Set Up Python Virtual Environment
Initialize and activate your virtual environment:
```powershell
# Create virtual environment
python -m venv .venv

# Activate (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Activate (Linux/macOS)
source .venv/bin/activate
```

### 2. Install Project Dependencies
Install all required libraries:
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Create a `.env` file in the root directory. You can use the template below:

```ini
PORT=5000
SECRET_KEY=c359a35e2307df51abcf185ea9f5e3e29f8f4a3e76a6b5c4
JWT_SECRET=8167f2e15da3b48fcd452a382103f6f39d82cbfa56f916b7
ENCRYPTION_KEY=dGhpc2lzYTMyYnl0ZXNlY3JldGtleWZvcmFlczI1Ng==

# MongoDB Connection String (Atlas or Local)
MONGO_URI=mongodb+srv://your_user:your_password@cluster0.example.mongodb.net/secure-vault?retryWrites=true&w=majority
```

> [!TIP]
> The application is designed to be highly resilient. If your MongoDB Atlas instance is unreachable due to firewalls, network proxy setups, or IP whitelist restrictions, it will **automatically fall back to a local in-memory mongomock database** so you can continue running and testing the application instantly.

### 4. Running the Application
Start the Flask local development server:
```bash
python app.py
```
Open [http://127.0.0.1:5000/health](http://127.0.0.1:5000/health) to confirm the API backend is running.

### 5. Running Automated Tests
To run the full suite of integration tests:
```bash
python -m unittest tests/test_api.py
```

---

## 🔒 Security Architectures & Best Practices

### 1. AES-256-GCM Cryptographic Implementation
We utilize Authenticated Encryption with Associated Data (AEAD) using **AES-256-GCM**.
- Standard encryption keys are derived from your `.env` `ENCRYPTION_KEY` using **SHA-256** to guarantee a secure 32-byte key size.
- A cryptographically secure random **12-byte initialization vector (nonce)** is generated for *every single* encryption operation. This ensures that the same note or file content results in entirely unique ciphertexts if saved multiple times.
- Both the ciphertext and the nonce are stored. During retrieval, GCM verifies the integrity tags to ensure the ciphertext has not been tampered with.

### 2. Secure Disk File Encryption (Mitigating Path Injection)
- **Path Traversal Mitigation**: When a file is uploaded, we generate a cryptographically random **UUID v4 hex** value for its filename on the physical disk (e.g., `uploads/7f9a2b...`). The original filename is stored in MongoDB metadata. This completely eliminates Directory Traversal attacks (e.g., uploading a file named `../../../etc/passwd` to overwrite server configs).
- **In-Memory Streaming Decryption**: When a user downloads an authorized file, the encrypted bytes are read from disk and decrypted **entirely in memory**. The decrypted bytes are then streamed directly to the client as a Flask response. Decrypted plaintext bytes are **never** written to disk.
- **Allowed MIME-Types**: Uploads are restricted by extension *and* MIME-type verifying that only text, image (PNG, JPG, GIF), and PDF files are allowed.

### 3. JWT & Access Control
- Custom JWT middleware (`@token_required` in [middleware.py](file:///d:/Projects/vault/middleware.py)) intercepts requests to protected routes.
- The user ID is encoded inside the JWT payload.
- Every API endpoint verifies that the resource (Note or File) queried belongs to the requesting user (`user_id` matches document owner ID), implementing strict **Attribute-Based Access Control (ABAC)**.

### 4. Audit Logging System
- A dedicated MongoDB collection `logs` maintains an audit trail.
- Automatically logs user logins (success/failure), note creation/deletion, and file uploads/downloads.
- Documents include timestamps, IP addresses (retrieved from proxy-aware request context), user IDs, and statuses.

---

## 📬 API Route Reference

### Authentication (Public)
* **`POST /api/auth/register`**
  - Registers a new user. Performs email format validation and complex password enforcement.
  - *Payload*: `{"name": "Name", "email": "user@example.com", "password": "ComplexPassword123!"}`
* **`POST /api/auth/login`**
  - Authenticates a user and returns a JWT token.
  - *Payload*: `{"email": "user@example.com", "password": "ComplexPassword123!"}`

### Secure Notes (Protected - Requires JWT)
* **`POST /api/notes`**
  - Creates a note. Title and content are sanitized and encrypted using AES-256-GCM.
  - *Payload*: `{"title": "Note Title", "content": "Confidential Content"}`
* **`GET /api/notes`**
  - Returns a list of all notes owned by the authenticated user, decrypted in-flight.
* **`DELETE /api/notes/<note_id>`**
  - Deletes the specified note.

### Secure Files (Protected - Requires JWT)
* **`POST /api/files/upload`**
  - Uploads a file, encrypts it, writes it to disk, and stores metadata in MongoDB.
  - *Payload*: Multipart form data containing the `file` field.
* **`GET /api/files`**
  - Lists metadata for all uploaded files (names, sizes, types).
* **`GET /api/files/download/<file_id>`**
  - Decrypts the target file in memory and streams it to the user.
* **`DELETE /api/files/<file_id>`**
  - Deletes the encrypted file from the disk and removes its metadata from MongoDB.

---

## 🚀 How to Test with Postman

We have provided a complete Postman Collection containing all of these requests.
1. Open Postman.
2. Click **Import** and select the [postman_collection.json](file:///d:/Projects/vault/postman_collection.json) file in this directory.
3. The collection defines two variables:
   - `base_url`: Defaults to `http://localhost:5000`.
   - `jwt_token`: Set this variable after calling **Login User** by copying the returned token.
4. All protected endpoints are pre-configured to use the `{{jwt_token}}` variable under their Bearer Auth configurations.
