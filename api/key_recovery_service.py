"""
Key Recovery Service - Shamir's Secret Sharing
Splits master password into N shares, requires K shares to recover
"""
from shamir_mnemonic import shamir
import json
from datetime import datetime
from django.core.mail import send_mail
from django.conf import settings


class KeyRecoveryService:
    """
    Implements Shamir's Secret Sharing for institutional master password
    Default: 5 shares, 3 required to recover
    """
    
    @staticmethod
    def generate_recovery_shares(master_password, num_shares=5, threshold=3):
        """
        Split master password into N shares, requiring K to recover
        
        Args:
            master_password: The institutional master password to split
            num_shares: Total number of shares to create (default 5)
            threshold: Minimum shares needed to recover (default 3)
            
        Returns:
            dict with shares and metadata
        """
        # Convert password to bytes
        secret = master_password.encode('utf-8')
        
        # shamir-mnemonic requires even number of bytes
        # Pad with null byte if odd length
        if len(secret) % 2 != 0:
            secret = secret + b'\x00'
        
        # Store original length for recovery
        original_length = len(master_password.encode('utf-8'))
        
        # Generate shares using Shamir's Secret Sharing
        # group_threshold=1 means 1 group required
        # groups=[(threshold, num_shares)] means one group with threshold/num_shares
        shares = shamir.generate_mnemonics(
            group_threshold=1,
            groups=[(threshold, num_shares)],
            master_secret=secret
        )
        
        # Flatten the nested list (shamir returns [[share1, share2, ...]])
        share_list = shares[0]
        
        # Create recovery package
        recovery_package = {
            'shares': [
                {
                    'id': i + 1,
                    'share': ' '.join(share),  # Convert tuple of words to space-separated string
                    'created_at': datetime.now().isoformat(),
                    'threshold': threshold,
                    'total_shares': num_shares,
                    'original_length': original_length  # Store for correct recovery
                }
                for i, share in enumerate(share_list)
            ],
            'threshold': threshold,
            'total_shares': num_shares,
            'created_at': datetime.now().isoformat(),
            'algorithm': 'Shamir Secret Sharing (SLIP-39)',
            'original_length': original_length
        }
        
        return recovery_package
    
    @staticmethod
    def recover_password(shares_data):
        """
        Recover master password from K shares
        
        Args:
            shares_data: List of share strings (minimum K shares)
            
        Returns:
            Recovered master password or None if failed
        """
        if len(shares_data) < 3:
            raise ValueError(f"Need at least 3 shares, got {len(shares_data)}")
        
        try:
            # Convert space-separated strings back to tuples of words
            share_tuples = [tuple(share.split()) for share in shares_data]
            
            # Recover the secret
            secret_bytes = shamir.combine_mnemonics(share_tuples)
            
            # Remove padding if it was added (check for null byte at end)
            if secret_bytes[-1] == 0:
                secret_bytes = secret_bytes[:-1]
            
            # Decode back to string
            password = secret_bytes.decode('utf-8')
            
            return password
            
        except Exception as e:
            raise ValueError(f"Recovery failed: {e}")
    
    @staticmethod
    def distribute_shares(recovery_package, admin_emails):
        """
        Distribute recovery shares to admin email addresses
        
        Args:
            recovery_package: Output from generate_recovery_shares()
            admin_emails: List of admin email addresses (must match num_shares)
        """
        shares = recovery_package['shares']
        
        if len(admin_emails) != len(shares):
            raise ValueError(f"Need {len(shares)} admin emails, got {len(admin_emails)}")
        
        for i, (share_info, email) in enumerate(zip(shares, admin_emails)):
            subject = f"QCV System - Key Recovery Share #{share_info['id']}"
            
            message = f"""
CONFIDENTIAL - KEY RECOVERY SHARE

This is Recovery Share #{share_info['id']} of {share_info['total_shares']} for the QCV institutional master key.

Share Data (24-word mnemonic):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{share_info['share']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IMPORTANT SECURITY INFORMATION:
✓ Store this share securely (password manager, encrypted storage, or paper backup)
✓ {share_info['threshold']} shares are required to recover the master password
✓ Do NOT share this with unauthorized personnel
✓ Write down these words IN ORDER and keep them safe
✓ Test recovery periodically to ensure shares are valid

If the master password is lost:
1. Contact {share_info['threshold']} or more key holders
2. Collect their recovery shares
3. Run: python manage.py recover_master_password
4. Enter the shares when prompted

System: QCV Post-Quantum Cryptography System
Algorithm: {recovery_package['algorithm']}
Created: {share_info['created_at']}
Share ID: #{share_info['id']}

For recovery procedures, contact the system administrator.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DO NOT LOSE THIS SHARE - IT CANNOT BE REGENERATED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            
            # In production, actually send email
            # For now, just print (development)
            print(f"\n{'=' * 60}")
            print(f"SHARE #{share_info['id']} - {email}")
            print(f"{'=' * 60}")
            print(message)
            
            # Uncomment for production email sending:
            # send_mail(
            #     subject,
            #     message,
            #     settings.DEFAULT_FROM_EMAIL,
            #     [email],
            #     fail_silently=False,
            # )
    
    @staticmethod
    def save_recovery_metadata(recovery_package, institution):
        """
        Save recovery metadata (NOT the shares) to database
        
        Args:
            recovery_package: Output from generate_recovery_shares()
            institution: Institution model instance
        """
        metadata = {
            'threshold': recovery_package['threshold'],
            'total_shares': recovery_package['total_shares'],
            'created_at': recovery_package['created_at'],
            'algorithm': recovery_package['algorithm'],
            'shares_distributed': True,
            'original_length': recovery_package['original_length']
        }
        
        institution.recovery_metadata = json.dumps(metadata)
        institution.save()