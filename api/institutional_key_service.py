"""
Institutional Key Management Service
Handles institution-level master keys for file encryption
"""
import os
import base64
import logging
from django.conf import settings
from api.models import Institution
from api.pqc_crypto import pqc
from api.key_encryption import KeyEncryptionService

logger = logging.getLogger(__name__)


class InstitutionalKeyService:
    """Manages institutional master keys"""
    
    _instance = None
    _cached_institution = None
    _cached_private_key = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(InstitutionalKeyService, cls).__new__(cls)
        return cls._instance
    
    def get_institution(self):
        """Get or create the institution record"""
        if self._cached_institution is None:
            institution = Institution.objects.filter(is_active=True).first()
            if not institution:
                logger.error("❌ No active institution found! Run setup_institutional_keys first.")
                raise Exception("Institution not configured. Run: python manage.py setup_institutional_keys")
            self._cached_institution = institution
        return self._cached_institution
    
    def get_public_key(self):
        """Get institutional public key"""
        institution = self.get_institution()
        return institution.pqc_kem_public_key
    
    def get_private_key(self, master_password):
        """
        Decrypt and retrieve institutional private key
        
        Args:
            master_password: Master password for institutional key
            
        Returns:
            Decrypted private key (base64 string)
        """
        if self._cached_private_key is not None:
            return self._cached_private_key
            
        institution = self.get_institution()
        
        try:
            # Decrypt institutional private key
            decrypted_key = KeyEncryptionService.decrypt_key(
                encrypted_key=institution.pqc_kem_secret_key_encrypted,
                salt=institution.pqc_kem_secret_key_salt,
                nonce=institution.pqc_kem_secret_key_nonce,
                password=master_password
            )
            
            # Cache for session
            self._cached_private_key = decrypted_key
            logger.info(f"✅ Institutional private key decrypted (length: {len(decrypted_key)} chars)")
            
            return decrypted_key
            
        except Exception as e:
            logger.error(f"❌ Failed to decrypt institutional key: {e}")
            raise Exception("Invalid institutional master password")
    
    def clear_cache(self):
        """Clear cached keys (call on logout or after timeout)"""
        self._cached_private_key = None
        logger.info("🔒 Institutional key cache cleared")
    
    def encrypt_file_key(self, file_encryption_key):
        """
        Encrypt a file encryption key with institutional public key
        
        Args:
            file_encryption_key: AES key + IV (48 bytes total)
            
        Returns:
            dict with 'encapsulated_key' and 'protected_key'
        """
        try:
            institution = self.get_institution()
            
            # Use ML-KEM to encapsulate the file key
            # Returns dict with: 'ciphertext', 'protected_key', 'algorithm'
            result = pqc.encapsulate_key(
                file_encryption_key,
                institution.pqc_kem_public_key
            )
            
            logger.info(f"✅ File key encrypted with institutional key")
            
            return {
                'encapsulated_key': result['ciphertext'],  # KEM ciphertext
                'protected_key': result['protected_key']   # XORed key data
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to encrypt file key: {e}")
            raise
    
    def decrypt_file_key(self, encapsulated_key, protected_key, master_password):
        """
        Decrypt a file encryption key using institutional private key
        
        Args:
            encapsulated_key: Encapsulated key from ML-KEM
            protected_key: Ciphertext from ML-KEM
            master_password: Master password to decrypt institutional key
            
        Returns:
            48-byte key material (32 bytes AES key + 16 bytes IV)
        """
        try:
            # Get institutional private key
            private_key = self.get_private_key(master_password)
            
            # Decapsulate to recover file key
            key_material = pqc.decapsulate_key(
                encapsulated_key,
                protected_key,
                private_key
            )
            
            logger.info(f"✅ File key decrypted with institutional key")
            
            return key_material
            
        except Exception as e:
            logger.error(f"❌ Failed to decrypt file key: {e}")
            raise


# Singleton instance
institutional_key_service = InstitutionalKeyService()