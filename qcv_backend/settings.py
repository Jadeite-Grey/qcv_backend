"""
Django settings for the Quantalock (QCV) backend.
"""
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# ==========================================
# CORE / SECURITY
# ==========================================
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'change-me-in-.env')
DEBUG = os.environ.get('DJANGO_DEBUG', 'True') == 'True'
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

AUTH_USER_MODEL = 'api.User'

# ==========================================
# APPS
# ==========================================
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'rest_framework',
    'rest_framework.authtoken',
    'corsheaders',
    'django_otp',
    'django_otp.plugins.otp_totp',

    'api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # TODO: api.middleware.session_timeout.SessionTimeoutMiddleware — file not yet ported.
    # SessionStatusView reads settings.SESSION_TIMEOUT_WARNING and a
    # 'last_activity' session key that this middleware is expected to set.
    # TODO: api.middleware.suspicious_activity — file not yet ported.
]

ROOT_URLCONF = 'qcv_backend.urls'
WSGI_APPLICATION = 'qcv_backend.wsgi.application'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# ==========================================
# DATABASE (Postgres 18, matches earlier setup)
# ==========================================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'qcv_db'),
        'USER': os.environ.get('DB_USER', 'qcv_user'),
        'PASSWORD': os.environ.get('DB_PASSWORD', ''),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

# ==========================================
# DRF / AUTH
# ==========================================
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'api.authentication.ExpiringTokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

# Session timeout (used by SessionStatusView / LoginView)
SESSION_COOKIE_AGE = int(os.environ.get('SESSION_COOKIE_AGE', 28800))  # 8 hours, matches PQC key session
SESSION_TIMEOUT_WARNING = int(os.environ.get('SESSION_TIMEOUT_WARNING', 300))  # warn 5 min before expiry
SESSION_SAVE_EVERY_REQUEST = True

# ==========================================
# CORS (frontend dev server on :3000)
# ==========================================
CORS_ALLOWED_ORIGINS = os.environ.get(
    'CORS_ALLOWED_ORIGINS',
    'http://localhost:3000,http://127.0.0.1:3000'
).split(',')
CORS_ALLOW_CREDENTIALS = True

# ==========================================
# PASSWORD VALIDATION
# ==========================================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ==========================================
# INTERNATIONALIZATION
# ==========================================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Africa/Harare'
USE_I18N = True
USE_TZ = True

# ==========================================
# STATIC / MEDIA
# ==========================================
STATIC_URL = 'static/'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'
REPORTS_DIR = BASE_DIR / 'media' / 'reports'
os.makedirs(MEDIA_ROOT, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ==========================================
# QCV / INSTITUTIONAL SETTINGS
# ==========================================
# Never type this live during a demo — load from .env only.
INSTITUTIONAL_MASTER_PASSWORD = os.environ.get('INSTITUTIONAL_MASTER_PASSWORD')

INSTITUTION_NAME = os.environ.get('INSTITUTION_NAME', "QCV Quantalock Radiology")
INSTITUTION_PHONE = os.environ.get('INSTITUTION_PHONE', '+263 000 000 000')
INSTITUTION_EMAIL = os.environ.get('INSTITUTION_EMAIL', 'reports@qcv-radiology.health')

# ==========================================
# EMAIL (django.core.mail — used directly by views.py for
# activation / password-reset / report emails)
# ==========================================
if os.environ.get('SMTP_HOST'):
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = os.environ.get('SMTP_HOST')
    EMAIL_PORT = int(os.environ.get('SMTP_PORT', 587))
    EMAIL_USE_TLS = os.environ.get('SMTP_USE_TLS', 'True') == 'True'
    EMAIL_HOST_USER = os.environ.get('SMTP_USER', '')
    EMAIL_HOST_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
else:
    # No SMTP configured — print emails to the console instead of failing.
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', INSTITUTION_EMAIL)

# Azure Communication Services (used by email_service.py — optional,
# EmailService disables itself gracefully if these are blank)
AZURE_COMMUNICATION_CONNECTION_STRING = os.environ.get('AZURE_COMMUNICATION_CONNECTION_STRING', '')
AZURE_EMAIL_FROM = os.environ.get('AZURE_EMAIL_FROM', '')

# ==========================================
# CLOUD STORAGE (cloud_storage_service.py)
# ==========================================
# 'azure', 'minio', or 'both'. Default to minio-only for local dev,
# since it doesn't require a real Azure account to run.
CLOUD_STORAGE_MODE = os.environ.get('CLOUD_STORAGE_MODE', 'minio')

AZURE_STORAGE_ACCOUNT_NAME = os.environ.get('AZURE_STORAGE_ACCOUNT_NAME', '')
AZURE_STORAGE_ACCOUNT_KEY = os.environ.get('AZURE_STORAGE_ACCOUNT_KEY', '')
AZURE_STORAGE_CONTAINER = os.environ.get('AZURE_STORAGE_CONTAINER', 'qcv-encrypted-backups')

MINIO_ENDPOINT = os.environ.get('MINIO_ENDPOINT', 'localhost:9000')
MINIO_ACCESS_KEY = os.environ.get('MINIO_ACCESS_KEY', 'minioadmin')
MINIO_SECRET_KEY = os.environ.get('MINIO_SECRET_KEY', 'minioadmin')
MINIO_SECURE = os.environ.get('MINIO_SECURE', 'False') == 'True'
MINIO_BUCKET = os.environ.get('MINIO_BUCKET', 'qcv-encrypted-backups')

CLOUD_STORAGE_CAPACITY_GB = int(os.environ.get('CLOUD_STORAGE_CAPACITY_GB', 3000))

# ==========================================
# CACHE (used by DashboardStatsView)
# ==========================================
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'qcv-local-cache',
    }
}

# ==========================================
# LOGGING
# ==========================================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {'class': 'logging.StreamHandler'},
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
}