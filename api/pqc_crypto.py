"""
Production Post-Quantum Cryptography Module
Uses ML-KEM-1024 (Kyber) for key encapsulation
Uses ML-DSA-87 (Dilithium) for digital signatures
"""

import ctypes
import ctypes.util
import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import logging

logger = logging.getLogger(__name__)

class PQCrypto:
    """Post-Quantum Cryptography implementation using liboqs"""
    
    def __init__(self):
        # Load liboqs shared library
        try:
            lib_path = ctypes.util.find_library('oqs')
            if not lib_path:
                raise RuntimeError("liboqs not found")
            self.liboqs = ctypes.CDLL(lib_path)
            self._setup_function_signatures()
            logger.info("✅ PQCrypto initialized successfully")
        except Exception as e:
            logger.error(f"❌ Failed to initialize PQCrypto: {e}")
            raise
    
    def _setup_function_signatures(self):
        """Define C function signatures for liboqs"""
        # KEM functions
        self.liboqs.OQS_KEM_new.argtypes = [ctypes.c_char_p]
        self.liboqs.OQS_KEM_new.restype = ctypes.c_void_p
        
        self.liboqs.OQS_KEM_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.liboqs.OQS_KEM_keypair.restype = ctypes.c_int
        
        self.liboqs.OQS_KEM_encaps.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.liboqs.OQS_KEM_encaps.restype = ctypes.c_int
        
        self.liboqs.OQS_KEM_decaps.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.liboqs.OQS_KEM_decaps.restype = ctypes.c_int
        
        self.liboqs.OQS_KEM_free.argtypes = [ctypes.c_void_p]
        self.liboqs.OQS_KEM_free.restype = None
        
        # Signature functions
        self.liboqs.OQS_SIG_new.argtypes = [ctypes.c_char_p]
        self.liboqs.OQS_SIG_new.restype = ctypes.c_void_p
        
        self.liboqs.OQS_SIG_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.liboqs.OQS_SIG_keypair.restype = ctypes.c_int
        
        self.liboqs.OQS_SIG_sign.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p
        ]
        self.liboqs.OQS_SIG_sign.restype = ctypes.c_int
        
        self.liboqs.OQS_SIG_verify.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p
        ]
        self.liboqs.OQS_SIG_verify.restype = ctypes.c_int
        
        self.liboqs.OQS_SIG_free.argtypes = [ctypes.c_void_p]
        self.liboqs.OQS_SIG_free.restype = None
    
    def _hkdf_expand(self, shared_secret, length):
        """
        Derive key material of any length from shared secret using HKDF (RFC 5869)
        
        Args:
            shared_secret: bytes - 32-byte shared secret from ML-KEM
            length: int - desired output length in bytes
        
        Returns:
            bytes - derived key material of specified length
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=b'qcv-pacs-file-key-v1',
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)
    
    def generate_kem_keypair(self):
        """Generate ML-KEM-1024 keypair for key encapsulation"""
        try:
            kem = self.liboqs.OQS_KEM_new(b"ML-KEM-1024")
            if not kem:
                raise RuntimeError("Failed to create ML-KEM-1024 instance")
            
            # Get key sizes
            kem_struct = ctypes.cast(kem, ctypes.POINTER(ctypes.c_char * 1000)).contents
            public_key = ctypes.create_string_buffer(1568)  # ML-KEM-1024 public key size
            secret_key = ctypes.create_string_buffer(3168)  # ML-KEM-1024 secret key size
            
            result = self.liboqs.OQS_KEM_keypair(kem, public_key, secret_key)
            self.liboqs.OQS_KEM_free(kem)
            
            if result != 0:
                raise RuntimeError("KEM keypair generation failed")
            
            return {
                'public_key': base64.b64encode(public_key.raw).decode('utf-8'),
                'secret_key': base64.b64encode(secret_key.raw).decode('utf-8')
            }
        except Exception as e:
            logger.error(f"KEM keypair generation failed: {e}")
            raise
    
    def generate_sig_keypair(self):
        """Generate ML-DSA-87 keypair for signatures"""
        try:
            sig = self.liboqs.OQS_SIG_new(b"ML-DSA-87")
            if not sig:
                raise RuntimeError("Failed to create ML-DSA-87 instance")
            
            public_key = ctypes.create_string_buffer(2592)  # ML-DSA-87 public key size
            secret_key = ctypes.create_string_buffer(4896)  # ML-DSA-87 secret key size
            
            result = self.liboqs.OQS_SIG_keypair(sig, public_key, secret_key)
            self.liboqs.OQS_SIG_free(sig)
            
            if result != 0:
                raise RuntimeError("Signature keypair generation failed")
            
            return {
                'public_key': base64.b64encode(public_key.raw).decode('utf-8'),
                'secret_key': base64.b64encode(secret_key.raw).decode('utf-8')
            }
        except Exception as e:
            logger.error(f"Signature keypair generation failed: {e}")
            raise
    
    def encrypt_file(self, file_data, recipient_public_key):
        """
        Hybrid encryption: ML-KEM-1024 + AES-256-GCM
        1. Generate random AES key
        2. Encrypt file with AES-256-GCM
        3. Encapsulate AES key using ML-KEM-1024
        """
        try:
            # Step 1: Generate random AES key
            aes_key = os.urandom(32)
            
            # Step 2: Encrypt file with AES-256-GCM
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(file_data) + encryptor.finalize()
            tag = encryptor.tag
            
            # Step 3: Encapsulate AES key using ML-KEM-1024
            kem = self.liboqs.OQS_KEM_new(b"ML-KEM-1024")
            if not kem:
                raise RuntimeError("Failed to create ML-KEM-1024 instance")
            
            public_key_bytes = base64.b64decode(recipient_public_key)
            ciphertext_kem = ctypes.create_string_buffer(1568)  # ML-KEM-1024 ciphertext size
            shared_secret = ctypes.create_string_buffer(32)     # Shared secret size
            
            result = self.liboqs.OQS_KEM_encaps(kem, ciphertext_kem, shared_secret, public_key_bytes)
            self.liboqs.OQS_KEM_free(kem)
            
            if result != 0:
                raise RuntimeError("KEM encapsulation failed")
            
            # XOR AES key with shared secret for extra security
            protected_key = bytes(a ^ b for a, b in zip(aes_key, shared_secret.raw))
            
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'encapsulated_key': base64.b64encode(ciphertext_kem.raw).decode('utf-8'),
                'protected_aes_key': base64.b64encode(protected_key).decode('utf-8'),
                'algorithm': 'ML-KEM-1024 + AES-256-GCM',
                'version': '1.0'
            }
        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            raise
    
    def decrypt_file(self, encrypted_package, recipient_secret_key):
        """
        Decrypt file using ML-KEM-1024 + AES-256-GCM
        """
        try:
            # Decode components
            ciphertext = base64.b64decode(encrypted_package['ciphertext'])
            nonce = base64.b64decode(encrypted_package['nonce'])
            tag = base64.b64decode(encrypted_package['tag'])
            encapsulated_key = base64.b64decode(encrypted_package['encapsulated_key'])
            protected_aes_key = base64.b64decode(encrypted_package['protected_aes_key'])
            
            # Decapsulate to get shared secret
            kem = self.liboqs.OQS_KEM_new(b"ML-KEM-1024")
            if not kem:
                raise RuntimeError("Failed to create ML-KEM-1024 instance")
            
            secret_key_bytes = base64.b64decode(recipient_secret_key)
            shared_secret = ctypes.create_string_buffer(32)
            
            result = self.liboqs.OQS_KEM_decaps(kem, shared_secret, encapsulated_key, secret_key_bytes)
            self.liboqs.OQS_KEM_free(kem)
            
            if result != 0:
                raise RuntimeError("KEM decapsulation failed")
            
            # Recover AES key
            aes_key = bytes(a ^ b for a, b in zip(protected_aes_key, shared_secret.raw))
            
            # Decrypt file
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext
        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            raise
    
    def encapsulate_key(self, key_data, recipient_public_key):
        """
        Encapsulate a key using ML-KEM-1024 with HKDF key derivation
        
        Args:
            key_data: bytes - The key material to protect (e.g., AES key + nonce, 44 bytes)
            recipient_public_key: base64 string - Recipient's ML-KEM public key
        
        Returns:
            dict with:
                'ciphertext': base64 - KEM ciphertext (encapsulated shared secret)
                'protected_key': base64 - key_data XORed with HKDF-derived key
        """
        try:
            kem = self.liboqs.OQS_KEM_new(b"ML-KEM-1024")
            if not kem:
                raise RuntimeError("Failed to create ML-KEM-1024 instance")
            
            public_key_bytes = base64.b64decode(recipient_public_key)
            ciphertext_kem = ctypes.create_string_buffer(1568)  # ML-KEM-1024 ciphertext size
            shared_secret = ctypes.create_string_buffer(32)     # 32-byte shared secret
            
            result = self.liboqs.OQS_KEM_encaps(kem, ciphertext_kem, shared_secret, public_key_bytes)
            self.liboqs.OQS_KEM_free(kem)
            
            if result != 0:
                raise RuntimeError("KEM encapsulation failed")
            
            # H-04 FIX: Use HKDF to derive key material of required length
            key_bytes = self._hkdf_expand(shared_secret.raw, len(key_data))
            
            # XOR key_data with derived key for protection
            protected_key = bytes(a ^ b for a, b in zip(key_data, key_bytes))
            
            return {
                'ciphertext': base64.b64encode(ciphertext_kem.raw).decode('utf-8'),
                'protected_key': base64.b64encode(protected_key).decode('utf-8'),
                'algorithm': 'ML-KEM-1024 + HKDF-SHA256'
            }
        except Exception as e:
            logger.error(f"Key encapsulation failed: {e}")
            raise

    def decapsulate_key(self, ciphertext, protected_key, recipient_secret_key):
        """
        Decapsulate a key using ML-KEM-1024 with HKDF key derivation
        
        Args:
            ciphertext: base64 string - KEM ciphertext
            protected_key: base64 string - XORed key data
            recipient_secret_key: base64 string - Recipient's ML-KEM secret key
        
        Returns:
            bytes - The original key_data
        """
        try:
            kem = self.liboqs.OQS_KEM_new(b"ML-KEM-1024")
            if not kem:
                raise RuntimeError("Failed to create ML-KEM-1024 instance")
            
            secret_key_bytes = base64.b64decode(recipient_secret_key)
            ciphertext_bytes = base64.b64decode(ciphertext)
            protected_key_bytes = base64.b64decode(protected_key)
            
            shared_secret = ctypes.create_string_buffer(32)
            
            result = self.liboqs.OQS_KEM_decaps(kem, shared_secret, ciphertext_bytes, secret_key_bytes)
            self.liboqs.OQS_KEM_free(kem)
            
            if result != 0:
                raise RuntimeError("KEM decapsulation failed")
            
            # H-04 FIX: Use HKDF to derive same key material
            key_bytes = self._hkdf_expand(shared_secret.raw, len(protected_key_bytes))
            
            # XOR to recover original key
            original_key = bytes(a ^ b for a, b in zip(protected_key_bytes, key_bytes))
            
            return original_key
        except Exception as e:
            logger.error(f"Key decapsulation failed: {e}")
            raise

    def sign_data(self, data, signing_key):
        """Sign data using ML-DSA-87"""
        try:
            sig = self.liboqs.OQS_SIG_new(b"ML-DSA-87")
            if not sig:
                raise RuntimeError("Failed to create ML-DSA-87 instance")
            
            secret_key_bytes = base64.b64decode(signing_key)
            signature = ctypes.create_string_buffer(4627)  # ML-DSA-87 signature size
            signature_len = ctypes.c_size_t(4627)
            
            result = self.liboqs.OQS_SIG_sign(
                sig, signature, ctypes.byref(signature_len),
                data, len(data), secret_key_bytes
            )
            self.liboqs.OQS_SIG_free(sig)
            
            if result != 0:
                raise RuntimeError("Signing failed")
            
            return base64.b64encode(signature.raw[:signature_len.value]).decode('utf-8')
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise
    
    def verify_signature(self, data, signature, public_key):
        """Verify ML-DSA-87 signature"""
        try:
            # Decode base64 inputs if they're strings
            if isinstance(signature, str):
                signature_bytes = base64.b64decode(signature.strip())
            else:
                signature_bytes = signature
            
            if isinstance(public_key, str):
                public_key_bytes = base64.b64decode(public_key.strip())
            else:
                public_key_bytes = public_key
            
            # Create ML-DSA-87 signature instance
            sig = self.liboqs.OQS_SIG_new(b"ML-DSA-87")
            if not sig:
                raise RuntimeError("Failed to create ML-DSA-87 instance")
            
            # Verify signature using liboqs
            result = self.liboqs.OQS_SIG_verify(
                sig,
                data, len(data),
                signature_bytes, len(signature_bytes),
                public_key_bytes
            )
            
            self.liboqs.OQS_SIG_free(sig)
            
            # result == 0 means SUCCESS in liboqs
            is_valid = (result == 0)
            
            if is_valid:
                logger.info("✅ Signature verification PASSED")
            else:
                logger.warning("⚠️ Signature verification FAILED - invalid signature")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False


# Singleton instance
pqc = PQCrypto()