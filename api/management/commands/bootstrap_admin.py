import os
from django.core.management.base import BaseCommand
from api.models import User
from api.pqc_crypto import pqc
from api.key_encryption import KeyEncryptionService


class Command(BaseCommand):
    help = "Create an initial admin user with real PQC keys from environment variables, if one doesn't already exist. Safe to run on every deploy."

    def handle(self, *args, **options):
        username = os.environ.get('ADMIN_USERNAME')
        password = os.environ.get('ADMIN_PASSWORD')
        email = os.environ.get('ADMIN_EMAIL', '')
        worker_id = os.environ.get('ADMIN_WORKER_ID', username or 'ADMIN-01')
        institution = os.environ.get('ADMIN_INSTITUTION', 'QCV PACS Dicom Imaging')

        if not username or not password:
            self.stdout.write(self.style.WARNING(
                'ADMIN_USERNAME / ADMIN_PASSWORD not set — skipping admin bootstrap.'
            ))
            return

        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(
                f'User "{username}" already exists — skipping admin bootstrap.'
            ))
            return

        user = User.objects.create_superuser(
            username=username,
            email=email,
            password=password,
            worker_id=worker_id,
            institution=institution,
            role='admin',
            is_activated=True,
        )

        # === PQC keypair generation, encrypted with the same password used to log in ===
        # Mirrors CreateUserView exactly, so this admin can decrypt/sign like any
        # normally created user instead of hitting "no encrypted PQC keys" at login.
        kem_keys = pqc.generate_kem_keypair()
        sig_keys = pqc.generate_sig_keypair()
        kem_encrypted = KeyEncryptionService.encrypt_key(kem_keys['secret_key'], password)
        sig_encrypted = KeyEncryptionService.encrypt_key(sig_keys['secret_key'], password)
        user.pqc_kem_public_key = kem_keys['public_key']
        user.pqc_kem_secret_key_encrypted = kem_encrypted['encrypted_key']
        user.pqc_kem_secret_key_salt = kem_encrypted['salt']
        user.pqc_kem_secret_key_nonce = kem_encrypted['nonce']
        user.pqc_sig_public_key = sig_keys['public_key']
        user.pqc_sig_secret_key_encrypted = sig_encrypted['encrypted_key']
        user.pqc_sig_secret_key_salt = sig_encrypted['salt']
        user.pqc_sig_secret_key_nonce = sig_encrypted['nonce']
        user.pqc_enabled = True
        user.save()

        self.stdout.write(self.style.SUCCESS(f'Created admin user with PQC keys: {username}'))
