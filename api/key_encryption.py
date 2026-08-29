# api/key_encryption.py
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import logging

logger = logging.getLogger(__name__)

class KeyEncryptionService:
    """Encrypt/decrypt PQC keys using user password"""
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes) -> bytes:
        """Derive 256-bit encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,  # OWASP recommendation for 2024
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def encrypt_key(plaintext_key: str, password: str) -> dict:
        """
        Encrypt a PQC key with user password
        
        Returns:
            {
                'encrypted_key': base64 encrypted data,
                'salt': base64 salt for key derivation,
                'nonce': base64 nonce for AES-GCM
            }
        """
        # Generate random salt and nonce
        salt = os.urandom(32)
        nonce = os.urandom(12)
        
        # Derive encryption key from password
        encryption_key = KeyEncryptionService.derive_key_from_password(password, salt)
        
        # Encrypt the PQC key
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        plaintext_bytes = plaintext_key.encode('utf-8')
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        tag = encryptor.tag
        
        return {
            'encrypted_key': base64.b64encode(ciphertext + tag).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8')
        }
    
    @staticmethod
    def decrypt_key(encrypted_key: str, salt: str, nonce: str, password: str) -> str:
        """
        Decrypt a PQC key with user password
        
        Returns:
            Plaintext PQC key (base64)
        """
        # Decode inputs
        ciphertext_and_tag = base64.b64decode(encrypted_key)
        ciphertext = ciphertext_and_tag[:-16]  # Last 16 bytes are tag
        tag = ciphertext_and_tag[-16:]
        salt_bytes = base64.b64decode(salt)
        nonce_bytes = base64.b64decode(nonce)
        
        # Derive decryption key from password
        decryption_key = KeyEncryptionService.derive_key_from_password(password, salt_bytes)
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(decryption_key),
            modes.GCM(nonce_bytes, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')