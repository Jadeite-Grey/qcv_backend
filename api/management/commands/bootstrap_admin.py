import os
from django.core.management.base import BaseCommand
from api.models import User


class Command(BaseCommand):
    help = "Create an initial admin user from environment variables, if one doesn't already exist. Safe to run on every deploy."

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

        User.objects.create_superuser(
            username=username,
            email=email,
            password=password,
            worker_id=worker_id,
            institution=institution,
            role='admin',
            is_activated=True,
        )
        self.stdout.write(self.style.SUCCESS(f'Created admin user: {username}'))
