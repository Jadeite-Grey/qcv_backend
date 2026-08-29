"""
QCV Encryption Service
AES-256-GCM authenticated encryption for DICOM files
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import logging
import os

logger = logging.getLogger(__name__)


class CryptoService:
    """Handles AES-256-GCM authenticated encryption for DICOM files"""
    
    AES_KEY_SIZE = 32  # 256 bits
    GCM_NONCE_SIZE = 12  # 96 bits (recommended for GCM)
    GCM_TAG_SIZE = 16  # 128 bits
    
    def __init__(self):
        """Initialize crypto service"""
        pass
    
    def generate_aes_key(self):
        """
        Generate a random 256-bit AES key
        
        Returns:
            bytes: 32-byte AES key
        """
        key = get_random_bytes(self.AES_KEY_SIZE)
        logger.info("Generated new AES-256 key")
        return key
    
    def encrypt_file(self, file_data: bytes, aes_key: bytes = None):
        """
        Encrypt file data using AES-256-GCM (authenticated encryption)
        
        Wire format: [12-byte nonce | 16-byte auth tag | ciphertext]
        
        Args:
            file_data: Raw file bytes to encrypt
            aes_key: AES key (generated if not provided)
            
        Returns:
            tuple: (encrypted_data_with_nonce_and_tag, aes_key, nonce)
        """
        try:
            # Generate key if not provided
            if aes_key is None:
                aes_key = self.generate_aes_key()
            
            # Generate random nonce (GCM doesn't use IV, uses nonce)
            nonce = get_random_bytes(self.GCM_NONCE_SIZE)
            
            # Create GCM cipher
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            
            # Encrypt and get authentication tag
            ciphertext, tag = cipher.encrypt_and_digest(file_data)
            
            # Pack: nonce + tag + ciphertext
            encrypted_data = nonce + tag + ciphertext
            
            logger.info(f"File encrypted (GCM): {len(file_data)} bytes → {len(encrypted_data)} bytes")
            
            return encrypted_data, aes_key, nonce
            
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise Exception(f"Encryption error: {str(e)}")
    
    def decrypt_file(self, encrypted_data: bytes, aes_key: bytes, nonce: bytes):
        """
        Decrypt file data using AES-256-GCM
        
        Wire format: [12-byte nonce | 16-byte auth tag | ciphertext]
        
        Args:
            encrypted_data: Encrypted file bytes (nonce + tag + ciphertext)
            aes_key: AES decryption key
            nonce: Nonce used during encryption (for backward compat, extracted from data if needed)
            
        Returns:
            bytes: Decrypted file data
        """
        try:
            # Extract nonce, tag, ciphertext from wire format
            nonce_from_data = encrypted_data[:self.GCM_NONCE_SIZE]
            tag = encrypted_data[self.GCM_NONCE_SIZE:self.GCM_NONCE_SIZE + self.GCM_TAG_SIZE]
            ciphertext = encrypted_data[self.GCM_NONCE_SIZE + self.GCM_TAG_SIZE:]
            
            # Create cipher with extracted nonce
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce_from_data)
            
            # Decrypt and verify authentication tag
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            
            logger.info(f"File decrypted (GCM): {len(encrypted_data)} bytes → {len(decrypted_data)} bytes")
            
            return decrypted_data
            
        except ValueError as e:
            logger.error(f"GCM decryption failed - Authentication tag mismatch: {str(e)}")
            raise Exception("Decryption failed: File was tampered with or invalid key")
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise Exception(f"Decryption error: {str(e)}")
    
    def decrypt_legacy_cbc(self, encrypted_data: bytes, aes_key: bytes, iv: bytes):
        """
        Decrypt LEGACY files encrypted with AES-256-CBC (read-only, no new CBC encryption)
        
        Args:
            encrypted_data: Encrypted file bytes (ciphertext only, no tag)
            aes_key: AES decryption key
            iv: Initialization vector used during encryption
            
        Returns:
            bytes: Decrypted file data
        """
        try:
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_data)
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            
            logger.warning(f"Legacy CBC file decrypted: {len(encrypted_data)} bytes (recommend re-encrypting with GCM)")
            
            return decrypted_data
            
        except ValueError as e:
            logger.error(f"Legacy CBC decryption failed - Invalid padding: {str(e)}")
            raise Exception("Decryption failed: Invalid key or corrupted data")
        except Exception as e:
            logger.error(f"Legacy CBC decryption failed: {str(e)}")
            raise Exception(f"Decryption error: {str(e)}")
    
    def encrypt_file_to_path(self, source_path: str, destination_path: str):
        """
        Encrypt a file from disk and save to new location (uses GCM)
        
        Args:
            source_path: Path to plaintext file
            destination_path: Path to save encrypted file
            
        Returns:
            tuple: (aes_key, nonce)
        """
        try:
            with open(source_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data, aes_key, nonce = self.encrypt_file(file_data)
            
            os.makedirs(os.path.dirname(destination_path), exist_ok=True)
            
            with open(destination_path, 'wb') as f:
                f.write(encrypted_data)
            
            logger.info(f"File encrypted (GCM) and saved: {destination_path}")
            
            return aes_key, nonce
            
        except Exception as e:
            logger.error(f"File encryption failed: {str(e)}")
            raise
    
    def decrypt_file_from_path(self, encrypted_path: str, aes_key: bytes, nonce: bytes):
        """
        Decrypt a GCM-encrypted file from disk and return decrypted data
        
        Args:
            encrypted_path: Path to encrypted file
            aes_key: AES decryption key
            nonce: Nonce (will be extracted from file if using wire format)
            
        Returns:
            bytes: Decrypted file data
        """
        try:
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.decrypt_file(encrypted_data, aes_key, nonce)
            
            logger.info(f"File decrypted from: {encrypted_path}")
            
            return decrypted_data
            
        except Exception as e:
            logger.error(f"File decryption failed: {str(e)}")
            raise
    
    def decrypt_legacy_cbc_from_path(self, encrypted_path: str, aes_key: bytes, iv: bytes):
        """
        Decrypt a LEGACY CBC-encrypted file from disk (read-only)
        
        Args:
            encrypted_path: Path to encrypted file
            aes_key: AES decryption key
            iv: Initialization vector
            
        Returns:
            bytes: Decrypted file data
        """
        try:
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.decrypt_legacy_cbc(encrypted_data, aes_key, iv)
            
            logger.warning(f"Legacy CBC file decrypted from: {encrypted_path}")
            
            return decrypted_data
            
        except Exception as e:
            logger.error(f"Legacy CBC file decryption failed: {str(e)}")
            raise


# Singleton instance
crypto_service = CryptoService()