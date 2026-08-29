"""
Management command: setup_institutional_keys

Creates the single active Institution row with a fresh ML-KEM-1024
keypair. The secret key is encrypted at rest with the institutional
master password (settings.INSTITUTIONAL_MASTER_PASSWORD), using the
same PBKDF2 + AES-GCM scheme KeyEncryptionService uses for per-user
keys.

Run once per environment:
    python manage.py setup_institutional_keys
    python manage.py setup_institutional_keys --name "St. Jude's Diagnostic Imaging"
    python manage.py setup_institutional_keys --force   # replace an existing active institution
"""
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from api.models import Institution
from api.pqc_crypto import pqc
from api.key_encryption import KeyEncryptionService


class Command(BaseCommand):
    help = "Bootstrap the institutional ML-KEM-1024 keypair used to encrypt all file keys."

    def add_arguments(self, parser):
        parser.add_argument(
            '--name',
            type=str,
            default=None,
            help="Institution name. Defaults to settings.INSTITUTION_NAME if not provided.",
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help="Archive the existing active institution and create a new one.",
        )

    def handle(self, *args, **options):
        master_password = getattr(settings, 'INSTITUTIONAL_MASTER_PASSWORD', None)
        if not master_password:
            raise CommandError(
                "INSTITUTIONAL_MASTER_PASSWORD is not set. Add it to your .env / settings "
                "before running this command, never type it live during a demo."
            )

        existing = Institution.objects.filter(is_active=True).first()
        if existing and not options['force']:
            self.stdout.write(self.style.WARNING(
                f"An active institution already exists: '{existing.name}' (v{existing.key_version}). "
                f"Nothing to do. Pass --force to rotate to a new key."
            ))
            return

        name = options['name'] or getattr(settings, 'INSTITUTION_NAME', None)
        if not name:
            raise CommandError(
                "No institution name provided and settings.INSTITUTION_NAME is not set. "
                "Pass --name \"Your Institution\"."
            )

        self.stdout.write("Generating ML-KEM-1024 institutional keypair...")
        kem_keys = pqc.generate_kem_keypair()

        self.stdout.write("Encrypting secret key with the institutional master password...")
        encrypted = KeyEncryptionService.encrypt_key(
            kem_keys['secret_key'],
            master_password,
        )

        if existing and options['force']:
            existing.is_active = False
            existing.save()
            new_version = existing.key_version + 1
            self.stdout.write(self.style.WARNING(
                f"Archived previous institution '{existing.name}' v{existing.key_version}. "
                f"Files encrypted under the old key remain readable via Institution.previous_version."
            ))
        else:
            new_version = 1

        institution = Institution.objects.create(
            name=name,
            pqc_kem_public_key=kem_keys['public_key'],
            pqc_kem_secret_key_encrypted=encrypted['encrypted_key'],
            pqc_kem_secret_key_salt=encrypted['salt'],
            pqc_kem_secret_key_nonce=encrypted['nonce'],
            key_version=new_version,
            is_active=True,
            replaced_by=None,
        )

        if existing and options['force']:
            existing.replaced_by = institution
            existing.save()

        self.stdout.write(self.style.SUCCESS(
            f"Institution '{institution.name}' created (key version {institution.key_version})."
        ))
        self.stdout.write(
            "Verify it's usable with: python manage.py shell\n"
            "  >>> from api.institutional_key_service import institutional_key_service\n"
            "  >>> institutional_key_service.get_public_key()\n"
            "This should return a base64 string without raising."
        )