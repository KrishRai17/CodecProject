import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _derive_key(secret: str) -> bytes:
    """
    Derive a 32-byte key from a secret string using SHA-256.
    Ensures any arbitrary secret length is securely mapped to a standard key length.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(secret.encode('utf-8'))
    return digest.finalize()

def encrypt_string(plain_text: str, secret: str) -> tuple[str, str]:
    """
    Encrypt a string using AES-256-GCM.
    Returns:
        (ciphertext_b64, nonce_b64)
    """
    if not plain_text:
        return "", ""
    key = _derive_key(secret)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode('utf-8'), None)
    return (
        base64.urlsafe_b64encode(ciphertext).decode('utf-8'),
        base64.urlsafe_b64encode(nonce).decode('utf-8')
    )

def decrypt_string(cipher_text_b64: str, nonce_b64: str, secret: str) -> str:
    """
    Decrypt a base64 encoded AES-256-GCM ciphertext using the given base64 encoded nonce.
    Returns:
        Decrypted plain text string.
    """
    if not cipher_text_b64 or not nonce_b64:
        return ""
    key = _derive_key(secret)
    aesgcm = AESGCM(key)
    cipher_bytes = base64.urlsafe_b64decode(cipher_text_b64.encode('utf-8'))
    nonce = base64.urlsafe_b64decode(nonce_b64.encode('utf-8'))
    plain_bytes = aesgcm.decrypt(nonce, cipher_bytes, None)
    return plain_bytes.decode('utf-8')

def encrypt_bytes(plain_bytes: bytes, secret: str) -> tuple[bytes, bytes]:
    """
    Encrypt raw bytes using AES-256-GCM.
    Returns:
        (ciphertext_bytes, nonce_bytes)
    """
    key = _derive_key(secret)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plain_bytes, None)
    return ciphertext, nonce

def decrypt_bytes(cipher_bytes: bytes, nonce: bytes, secret: str) -> bytes:
    """
    Decrypt raw bytes using AES-256-GCM.
    Returns:
        Decrypted raw bytes.
    """
    key = _derive_key(secret)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, cipher_bytes, None)
