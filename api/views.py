"""
Quantalock API views — Chunk 1 of N.

This chunk contains:
  - Shared helper functions (get_client_ip, create_audit_log,
    validate_password_strength)
  - Auth: LoginView, SessionStatusView, LogoutView
  - RIS Worklist (new — did not exist in the old file/PACS-only backend):
      ListOrdersView, CreateOrderView, UpdateOrderStatusView

Append subsequent chunks (upload/files, reports, dashboard/health,
users/admin, cloud sync/alerts/recovery, security dashboard) to the
SAME views.py file, below this chunk. Do not create separate files
per chunk — urls.py imports everything from one views module, same
as your original.
"""

import os
import re
import time
import html
import secrets
import logging
from datetime import timedelta, datetime

from django.conf import settings
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.utils import timezone
from django.db.models import Q
from django_otp import match_token

from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import User, DicomFile, DicomSeries, AuditLog, PatientReport, ExpiringToken
from .serializers import (
    DicomSeriesSerializer,
    DicomSeriesCreateSerializer,
)
from api.pqc_crypto import pqc
from api.crypto_service import crypto_service
from api.institutional_key_service import institutional_key_service
from api.key_encryption import KeyEncryptionService

logger = logging.getLogger(__name__)


# ==========================================
# SHARED HELPERS
# ==========================================

def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def create_audit_log(user, action, dicom_file=None, series=None, success=True,
                      error_message=None, details='', request=None):
    """Helper function to create audit log entries"""
    try:
        AuditLog.objects.create(
            user=user,
            action=action,
            dicom_file=dicom_file,
            series=series,
            success=success,
            error_message=error_message,
            details=details,
            ip_address=get_client_ip(request) if request else '127.0.0.1',
            user_agent=request.META.get('HTTP_USER_AGENT', '') if request else ''
        )
    except Exception as e:
        logger.error(f"Failed to create audit log: {str(e)}")


def validate_password_strength(password):
    """Enforce strong password requirements"""
    if not password:
        raise ValidationError("Password is required")
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long")
    weak_passwords = ['password', '12345678', 'qwerty123', 'admin123']
    if password.lower() in weak_passwords:
        raise ValidationError("Password is too common - please choose a stronger password")
    if not re.search(r'[a-zA-Z]', password):
        raise ValidationError("Password must contain at least one letter")
    if not re.search(r'\d', password):
        raise ValidationError("Password must contain at least one number")
    return True


# ==========================================
# 1. AUTH
# ==========================================

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        start_time = time.perf_counter()

        username = request.data.get('username')
        password = request.data.get('password')
        totp_code = request.data.get('totp_code')

        if not username or not password:
            return Response(
                {'error': 'Username and password required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(request=request, username=username, password=password)

        # Constant-time-ish delay so failed/successful logins aren't
        # distinguishable by response time (mirrors the timing-attack
        # test from the dissertation's security suite).
        elapsed = time.perf_counter() - start_time
        if elapsed < 0.6:
            time.sleep(0.6 - elapsed)

        if not user:
            create_audit_log(
                user=None, action='FAILED_LOGIN', success=False,
                error_message=f'Failed login attempt for username: {username}',
                request=request
            )
            logger.warning(f"Failed login attempt for {username}")
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        if user.two_factor_enabled:
            if not totp_code:
                return Response({
                    'error': '2FA code required',
                    'requires_2fa': True
                }, status=status.HTTP_403_FORBIDDEN)

            if not match_token(user, totp_code):
                create_audit_log(
                    user=user, action='FAILED_2FA', success=False,
                    error_message='Invalid 2FA code', request=request
                )
                return Response({
                    'error': 'Invalid 2FA code',
                    'requires_2fa': True
                }, status=status.HTTP_403_FORBIDDEN)

            request.session['2fa_verified_at'] = timezone.now().isoformat()
            request.session['2fa_verified'] = True

        ExpiringToken.objects.filter(user=user).delete()
        token = ExpiringToken.objects.create(user=user)

        if user.password_reset_required:
            if user.password_reset_at:
                if timezone.now() - user.password_reset_at > timedelta(hours=24):
                    return Response({
                        'error': 'Your temporary password has expired. Please contact your administrator.',
                        'expired': True
                    }, status=status.HTTP_403_FORBIDDEN)

            return Response({
                'token': token.key,
                'expires_in': token.time_remaining,
                'user': {'id': str(user.id), 'username': user.username, 'role': user.role},
                'password_change_required': True,
                'message': 'You must change your password before continuing'
            }, status=status.HTTP_200_OK)

        login(request, user)

        # Decrypt per-user PQC keys with the login password, store
        # server-side in session only (never sent to the client).
        try:
            if user.pqc_kem_secret_key_encrypted and user.pqc_sig_secret_key_encrypted:
                kem_secret_key = KeyEncryptionService.decrypt_key(
                    user.pqc_kem_secret_key_encrypted,
                    user.pqc_kem_secret_key_salt,
                    user.pqc_kem_secret_key_nonce,
                    password
                )
                sig_secret_key = KeyEncryptionService.decrypt_key(
                    user.pqc_sig_secret_key_encrypted,
                    user.pqc_sig_secret_key_salt,
                    user.pqc_sig_secret_key_nonce,
                    password
                )
                request.session['pqc_kem_secret_key'] = kem_secret_key
                request.session['pqc_sig_secret_key'] = sig_secret_key
                request.session.set_expiry(28800)  # 8 hours
                logger.info(f"PQC keys decrypted and stored in session for {user.username}")
            else:
                logger.warning(f"User {user.username} has no encrypted PQC keys")
        except Exception as e:
            logger.error(f"Failed to decrypt PQC keys: {str(e)}")
            # Continue login even if key decryption fails — user just
            # won't be able to sign uploads until keys are regenerated.

        create_audit_log(user=user, action='LOGIN', success=True, request=request)

        return Response({
            'token': token.key,
            'expires_in': token.time_remaining,
            'user': {
                'id': str(user.id),
                'username': user.username,
                'role': user.role,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser,
            },
            'two_factor_enabled': user.two_factor_enabled
        }, status=status.HTTP_200_OK)


class SessionStatusView(APIView):
    """Check session status and time remaining"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            last_activity = request.session.get('last_activity')

            if not last_activity:
                return Response({
                    'active': True,
                    'time_remaining': settings.SESSION_COOKIE_AGE,
                    'warning': False
                })

            last_activity_time = timezone.datetime.fromisoformat(last_activity)
            time_since_activity = timezone.now() - last_activity_time
            timeout = timedelta(seconds=settings.SESSION_COOKIE_AGE)
            time_remaining = (timeout - time_since_activity).total_seconds()
            should_warn = time_remaining < settings.SESSION_TIMEOUT_WARNING

            return Response({
                'active': time_remaining > 0,
                'time_remaining': max(0, int(time_remaining)),
                'warning': should_warn,
                'last_activity': last_activity,
                'has_pqc_keys': 'pqc_kem_secret_key' in request.session
            })
        except Exception as e:
            logger.error(f"Session status check failed: {e}")
            return Response({'error': 'Failed to check session status'},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    """Logout and clear session-held PQC key material"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            request.session.pop('pqc_kem_secret_key', None)
            request.session.pop('pqc_sig_secret_key', None)
            request.session.modified = True

            if hasattr(request.user, 'auth_token'):
                request.user.auth_token.delete()

            create_audit_log(user=request.user, action='LOGOUT', success=True, request=request)

            logout(request)

            return Response({'message': 'Logged out successfully', 'keys_cleared': True},
                             status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Logout failed: {e}")
            return Response({'error': 'Logout failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ==========================================
# 2. RIS WORKLIST — new, replaces mock 'orders' data
# ==========================================

class ListOrdersView(APIView):
    """
    GET /worklist/  (or /orders/, wire either in urls.py)
    Backs the frontend worklist directly — one DicomSeries row per order.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        orders = DicomSeries.objects.all()

        status_filter = request.query_params.get('status')
        if status_filter and status_filter != 'all':
            orders = orders.filter(review_status=status_filter)

        modality = request.query_params.get('modality')
        if modality and modality != 'all':
            orders = orders.filter(modality__iexact=modality)

        priority = request.query_params.get('priority')
        if priority and priority != 'all':
            orders = orders.filter(priority=priority)

        search = request.query_params.get('search')
        if search:
            orders = orders.filter(
                Q(patient_name__icontains=search) |
                Q(patient_id__icontains=search) |
                Q(accession_number__icontains=search) |
                Q(referring_physician__icontains=search)
            )

        orders = orders.order_by('-order_created_at')
        serializer = DicomSeriesSerializer(orders, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CreateOrderView(APIView):
    """
    POST /worklist/create/
    Backs the frontend's 'New Order' modal. Creates a DicomSeries row
    with review_status='pending' and no files attached yet — files get
    linked to it later via UploadDicomView's series_id field.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if request.user.role not in ['admin', 'doctor', 'nurse', 'radiologist']:
            return Response({'error': 'Only clinical staff can create orders'},
                             status=status.HTTP_403_FORBIDDEN)

        serializer = DicomSeriesCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        accession_number = f"ACC-{timezone.now().strftime('%Y')}-{secrets.randbelow(900000) + 100000}"

        order = DicomSeries.objects.create(
            accession_number=accession_number,
            patient_id=data['patient_id'],
            patient_name=data['patient_name'],
            patient_dob=data.get('patient_dob'),
            modality=data['modality'],
            body_part=data['body_part'],
            referring_physician=data['referring_physician'],
            priority=data.get('priority', 'routine'),
            clinical_indication=data.get('clinical_indication', ''),
            review_status='pending',
            uploaded_by=request.user,
        )

        create_audit_log(
            user=request.user, action='ORDER_CREATED', series=order, success=True,
            details=f"Order created: {accession_number} for {order.patient_name}",
            request=request
        )

        return Response(DicomSeriesSerializer(order).data, status=status.HTTP_201_CREATED)


class UpdateOrderStatusView(APIView):
    """
    PATCH /worklist/<order_id>/status/
    Moves an order through pending -> in_progress -> finalized.
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, order_id):
        try:
            order = DicomSeries.objects.get(id=order_id)
        except DicomSeries.DoesNotExist:
            return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

        new_status = request.data.get('review_status')
        valid_statuses = [choice[0] for choice in DicomSeries.REVIEW_STATUS_CHOICES]
        if new_status not in valid_statuses:
            return Response(
                {'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        old_status = order.review_status
        order.review_status = new_status
        if new_status == 'in_progress' and not order.assigned_radiologist:
            order.assigned_radiologist = request.user
        order.save()

        create_audit_log(
            user=request.user, action='ORDER_STATUS_CHANGED', series=order, success=True,
            details=f"Status changed {old_status} -> {new_status} for {order.accession_number}",
            request=request
        )

        return Response(DicomSeriesSerializer(order).data, status=status.HTTP_200_OK)

"""
Quantalock API views — Chunk 2 of N.

APPEND this to the bottom of the SAME api/views.py file that already
has Chunk 1 (helpers, auth, worklist). Add these imports to the top
of that file, alongside the Chunk 1 imports:

    import uuid
    import pydicom
    from io import BytesIO
    from django.http import HttpResponse
    from rest_framework.parsers import MultiPartParser, FormParser
    from .models import DicomFile as _DicomFile  # already imported in chunk 1, no dup needed
    from .serializers import DicomFileSerializer, DicomFileUploadSerializer
    from .dicom_utils import get_dicom_viewer_metadata

This chunk contains:
  - UploadDicomView   (fixed: now actually creates/links a DicomSeries
    row, the old version wrote series fields onto DicomFile directly
    and never touched the DicomSeries table at all)
  - ListDicomFilesView
  - GetFileDetailsView
  - DownloadDicomView
  - ViewDicomFileView (extended: now returns real per-slice windowing
    metadata in response headers alongside the decrypted image bytes,
    sourced from get_dicom_viewer_metadata() in the fixed dicom_utils.py)
  - DeleteDicomFileView
"""

import uuid
import pydicom
from io import BytesIO
from django.http import HttpResponse
from rest_framework.parsers import MultiPartParser, FormParser

from .serializers import DicomFileSerializer, DicomFileUploadSerializer
from .dicom_utils import get_dicom_viewer_metadata


class UploadDicomView(APIView):
    """
    Upload and encrypt DICOM files with INSTITUTIONAL PQC.

    Fix vs. the old version: files are now actually linked to a
    DicomSeries row (the RIS worklist order), either an existing one
    passed as series_id, or a new ad-hoc one created on the fly for
    standalone/legacy uploads not tied to a pre-created order.
    """
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        if request.user.role not in ['admin', 'doctor', 'nurse', 'radiologist']:
            return Response({'error': 'Only clinical staff can upload files'},
                             status=status.HTTP_403_FORBIDDEN)
        try:
            files = request.FILES.getlist('files')
            if not files:
                single_file = request.FILES.get('file')
                if single_file:
                    files = [single_file]
                else:
                    return Response({'error': 'No files provided'}, status=status.HTTP_400_BAD_REQUEST)

            # --- File type validation (unchanged from original) ---
            ALLOWED_MIME_TYPES = ['application/dicom', 'application/octet-stream']

            for file in files:
                file_ext = os.path.splitext(file.name)[1].lower()
                if file_ext not in ['.dcm', '.dicom'] and not file.name.upper().endswith('.DCM'):
                    return Response({
                        'error': f'Invalid file type: {file.name}. Only DICOM files (.dcm, .dicom) are allowed.'
                    }, status=status.HTTP_400_BAD_REQUEST)

                content_type = file.content_type
                if content_type not in ALLOWED_MIME_TYPES:
                    logger.warning(f"Rejected file {file.name} with MIME type {content_type}")
                    return Response({
                        'error': f'Invalid file type. Only DICOM files are allowed. Detected type: {content_type}'
                    }, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)

                try:
                    file.seek(0)
                    file_content = file.read()
                    file.seek(0)

                    if len(file_content) < 132:
                        return Response({'error': f'{file.name} is too small to be a valid DICOM file'},
                                         status=status.HTTP_400_BAD_REQUEST)

                    if file_content[128:132] != b'DICM':
                        try:
                            pydicom.dcmread(BytesIO(file_content), force=True)
                        except Exception as e:
                            logger.error(f"Not a valid DICOM file: {file.name} - {e}")
                            return Response({'error': f'{file.name} is not a valid DICOM file.'},
                                             status=status.HTTP_400_BAD_REQUEST)
                except Exception as e:
                    logger.error(f"File validation error for {file.name}: {e}")
                    return Response({'error': f'Failed to validate {file.name}'}, status=status.HTTP_400_BAD_REQUEST)

            logger.info(f"All {len(files)} file(s) passed DICOM validation")

            # --- Resolve the target order (DicomSeries) ---
            series_id = request.data.get('series_id')
            order = None
            if series_id:
                try:
                    order = DicomSeries.objects.get(id=series_id)
                except DicomSeries.DoesNotExist:
                    return Response({'error': 'series_id does not match an existing order'},
                                     status=status.HTTP_404_NOT_FOUND)

            patient_id = request.data.get('patientId', order.patient_id if order else '')
            patient_name_first = request.data.get('firstName', '')
            patient_name_last = request.data.get('lastName', '')
            study_date = request.data.get('studyDate', str(order.study_date) if order and order.study_date else '')
            modality = request.data.get('modality', order.modality if order else '')
            study_description = request.data.get('studyDescription', '')
            tag = request.data.get('tag', 'ROUTINE')
            series_description = request.data.get('seriesDescription', '')
            series_number = request.data.get('seriesNumber', '')
            is_series = request.data.get('is_series', 'false').lower() == 'true'
            condition = request.data.get('condition', '')
            body_region = request.data.get('bodyRegion', order.body_part if order else '')
            referring_doctor = request.data.get('referringDoctor', order.referring_physician if order else '')
            date_of_birth = request.data.get('dateOfBirth', '')

            if not order and not all([patient_id, study_date, modality]):
                return Response({'error': 'Missing required fields (or provide series_id of an existing order)'},
                                 status=status.HTTP_400_BAD_REQUEST)

            # No pre-created order — make an ad-hoc one so this upload
            # still shows up on the worklist rather than being orphaned.
            if not order:
                order = DicomSeries.objects.create(
                    accession_number=f"ACC-{timezone.now().strftime('%Y')}-{secrets.randbelow(900000) + 100000}",
                    patient_id=patient_id,
                    patient_name=f"{patient_name_last}^{patient_name_first}".strip('^'),
                    modality=modality,
                    body_part=body_region,
                    referring_physician=referring_doctor,
                    review_status='pending',
                    uploaded_by=request.user,
                )

            pqc_sig_secret_key = request.session.get('pqc_sig_secret_key')
            if not pqc_sig_secret_key:
                return Response({'error': 'Authentication keys not available'}, status=status.HTTP_401_UNAUTHORIZED)

            uploaded_files = []
            series_uid = None

            for idx, file in enumerate(files):
                try:
                    file_content = file.read()

                    try:
                        dataset = pydicom.dcmread(BytesIO(file_content), force=True)
                        study_instance_uid = str(dataset.get('StudyInstanceUID', ''))
                        series_instance_uid = str(dataset.get('SeriesInstanceUID', ''))
                        instance_number = int(dataset.get('InstanceNumber', idx + 1))
                        if is_series and not series_uid:
                            series_uid = series_instance_uid
                    except Exception as e:
                        logger.warning(f"Could not extract DICOM UIDs: {e}")
                        study_instance_uid = ''
                        series_instance_uid = ''
                        instance_number = idx + 1
                        if is_series and not series_uid:
                            series_uid = f"SERIES_{timezone.now().strftime('%Y%m%d%H%M%S')}"

                    # === INSTITUTIONAL PQC ENCRYPTION ===
                    encrypted_data, aes_key, iv = crypto_service.encrypt_file(file_content)
                    key_material = aes_key + iv  # 48 bytes total

                    master_password = getattr(settings, 'INSTITUTIONAL_MASTER_PASSWORD', None)
                    if not master_password:
                        raise Exception("INSTITUTIONAL_MASTER_PASSWORD not configured")

                    encrypted_key_package = institutional_key_service.encrypt_file_key(key_material)
                    pqc_signature = pqc.sign_data(encrypted_data, pqc_sig_secret_key)

                    dicom_file_id = str(uuid.uuid4())

                    patient_name = order.patient_name or f"{patient_name_last}^{patient_name_first}"

                    dicom_file = DicomFile.objects.create(
                        id=dicom_file_id,
                        original_filename=file.name,
                        file_path='',
                        encrypted_data=encrypted_data,
                        file_size=file.size,
                        patient_id=order.patient_id,
                        patient_name=patient_name,
                        study_date=study_date or None,
                        modality=modality,
                        study_description=study_description,
                        uploaded_by=request.user,

                        aes_key=aes_key,
                        iv=iv,
                        encryption_algorithm='INSTITUTIONAL_PQC',
                        pqc_encrypted=True,

                        institutional_encrypted_fek=encrypted_key_package['encapsulated_key'],
                        institutional_protected_key=encrypted_key_package['protected_key'],
                        encrypted_with_key_version=1,
                        pqc_signature=pqc_signature,

                        tag=tag,
                        study_instance_uid=study_instance_uid,
                        series_instance_uid=series_instance_uid,
                        series_description=series_description,
                        series_number=series_number,
                        instance_number=instance_number,
                        condition=condition,
                        body_region=body_region,
                        referring_doctor=referring_doctor,
                        date_of_birth=date_of_birth if date_of_birth else None,
                        is_part_of_series=is_series,
                        series_uid=series_uid if is_series else None,
                        cloud_backup_status='PENDING',

                        # THE FIX — files now actually attach to the order:
                        series=order,
                    )

                    uploaded_files.append(dicom_file)

                    create_audit_log(
                        user=request.user, action='FILE_UPLOAD', dicom_file=dicom_file, series=order,
                        success=True, details=f"INSTITUTIONAL_PQC: {file.name} ({idx + 1}/{len(files)})",
                        request=request
                    )

                    logger.info(f"File {idx + 1}/{len(files)} encrypted with INSTITUTIONAL_PQC: {file.name}")

                except Exception as file_error:
                    logger.error(f"Failed {file.name}: {file_error}")
                    continue

            if not uploaded_files:
                return Response({'error': 'Failed to upload any files'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Keep the order's slice counts in sync with what's actually attached.
            order.total_slices = order.files.filter(is_deleted=False).count()
            order.uploaded_slices = order.total_slices
            order.save()

            return Response({
                'message': f'Successfully uploaded {len(uploaded_files)} file(s)',
                'files_uploaded': len(uploaded_files),
                'series_uid': series_uid if is_series else None,
                'order_id': str(order.id),
                'accession_number': order.accession_number,
                'file_ids': [str(f.id) for f in uploaded_files]
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Upload error: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ListDicomFilesView(APIView):
    """List DICOM files (filtered by user role)"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            if request.user.role in ['admin', 'doctor', 'nurse', 'radiologist']:
                files = DicomFile.objects.filter(is_deleted=False)
            else:
                files = DicomFile.objects.filter(uploaded_by=request.user, is_deleted=False)

            tag = request.query_params.get('tag')
            if tag:
                files = files.filter(tag=tag)

            modality = request.query_params.get('modality')
            if modality:
                files = files.filter(modality=modality)

            files = files.order_by('-uploaded_at')
            serializer = DicomFileSerializer(files, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"List files failed: {str(e)}")
            return Response({'error': 'Failed to list files', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetFileDetailsView(APIView):
    """Get single file details"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, file_id):
        try:
            dicom_file = DicomFile.objects.get(id=file_id, is_deleted=False)
            if request.user.role not in ['admin', 'doctor', 'nurse', 'radiologist']:
                return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            serializer = DicomFileSerializer(dicom_file)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except DicomFile.DoesNotExist:
            return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)


def _decrypt_dicom_file(dicom_file):
    """
    Shared decrypt logic for DownloadDicomView and ViewDicomFileView.
    Returns decrypted bytes, or raises with a message meant to be
    shown to the user.
    """
    if not dicom_file.encrypted_data:
        raise FileNotFoundError('Encrypted data not found in database')

    if dicom_file.encryption_algorithm != 'INSTITUTIONAL_PQC':
        raise ValueError('This file uses legacy encryption and cannot be decrypted by this endpoint')

    master_password = getattr(settings, 'INSTITUTIONAL_MASTER_PASSWORD', None)
    if not master_password:
        raise RuntimeError('System configuration error — INSTITUTIONAL_MASTER_PASSWORD not set')

    key_material = institutional_key_service.decrypt_file_key(
        dicom_file.institutional_encrypted_fek,
        dicom_file.institutional_protected_key,
        master_password
    )
    aes_key = key_material[:32]
    iv = key_material[32:48]

    return crypto_service.decrypt_file(dicom_file.encrypted_data, aes_key, iv)


def _ensure_uncompressed_dicom(dicom_bytes):
    """
    If the DICOM's pixel data uses a compressed transfer syntax dwv
    can't decode (e.g. JPEG-LS), decompress it and re-serialize as
    Explicit VR Little Endian so the browser viewer can render it.
    Returns the original bytes unchanged if already uncompressed or
    if decompression isn't needed/possible.
    """
    try:
        import pydicom
        from pydicom.uid import ExplicitVRLittleEndian
        import io

        ds = pydicom.dcmread(io.BytesIO(dicom_bytes))
        if ds.file_meta.TransferSyntaxUID.is_compressed:
            ds.decompress()  # requires pylibjpeg + pylibjpeg-libjpeg installed
            ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
            buf = io.BytesIO()
            ds.save_as(buf, enforce_file_format=True)
            return buf.getvalue()
        return dicom_bytes
    except Exception as e:
        logger.warning(f"Could not decompress DICOM for viewing: {e}")
        return dicom_bytes


class DownloadDicomView(APIView):
    """Download DICOM file with 2FA verification"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, file_id):
        try:
            dicom_file = DicomFile.objects.get(id=file_id, is_deleted=False)

            if request.user.two_factor_enabled:
                verified_at = request.session.get('2fa_verified_at')
                if not verified_at:
                    return Response({'error': '2FA verification required for download', 'requires_2fa': True},
                                     status=status.HTTP_403_FORBIDDEN)
                verified_time = timezone.datetime.fromisoformat(verified_at)
                if timezone.now() - verified_time > timedelta(minutes=5):
                    del request.session['2fa_verified_at']
                    return Response({'error': '2FA verification expired. Please verify again.', 'requires_2fa': True},
                                     status=status.HTTP_403_FORBIDDEN)

            try:
                decrypted_data = _decrypt_dicom_file(dicom_file)
            except FileNotFoundError:
                return Response({'error': 'File not found on disk'}, status=status.HTTP_404_NOT_FOUND)
            except (ValueError, RuntimeError) as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f"Decryption failed: {e}")
                return Response({'error': 'Decryption failed', 'detail': str(e)},
                                 status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            create_audit_log(user=request.user, action='DOWNLOAD', dicom_file=dicom_file,
                              series=dicom_file.series, success=True, request=request)

            response = HttpResponse(decrypted_data, content_type='application/dicom')
            response['Content-Disposition'] = f'attachment; filename="{dicom_file.original_filename}"'
            return response

        except DicomFile.DoesNotExist:
            return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Download failed: {str(e)}", exc_info=True)
            return Response({'error': 'Download failed', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ViewDicomFileView(APIView):
    """
    Stream a decrypted DICOM file to the viewer.

    Extended vs. the old version: real per-slice windowing metadata
    (window width/center, pixel spacing, slice location) is extracted
    from the decrypted file and returned as response headers alongside
    the image bytes, so the frontend viewer has real values instead of
    filling in defaults itself.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, file_id):
        try:
            try:
                dicom_file = DicomFile.objects.get(id=file_id, is_deleted=False)
            except DicomFile.DoesNotExist:
                return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)

            clinical_roles = ['admin', 'doctor', 'nurse', 'radiologist']
            if request.user.role not in clinical_roles:
                create_audit_log(user=request.user, action='VIEW_DENIED', dicom_file=dicom_file,
                                  series=dicom_file.series, success=False,
                                  error_message='Non-clinical staff cannot view files', request=request)
                return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            # Verify signature before decrypting, same as original.
            if dicom_file.pqc_signature:
                if not dicom_file.encrypted_data:
                    return Response({'error': 'File not found in database'}, status=status.HTTP_404_NOT_FOUND)

                encrypted_data_for_sig = dicom_file.encrypted_data

                uploader = dicom_file.uploaded_by
                if uploader and uploader.pqc_sig_public_key:
                    try:
                        is_valid = pqc.verify_signature(
                            encrypted_data_for_sig, dicom_file.pqc_signature, uploader.pqc_sig_public_key
                        )
                        if not is_valid:
                            create_audit_log(
                                user=request.user, action='VIEW_DENIED_INVALID_SIGNATURE', dicom_file=dicom_file,
                                series=dicom_file.series, success=False,
                                error_message='File signature verification failed', request=request
                            )
                            return Response({
                                'error': 'File integrity verification failed',
                                'detail': 'This file signature is invalid. Contact administrator to re-sign files.',
                                'action_required': 'BULK_RESIGN'
                            }, status=status.HTTP_403_FORBIDDEN)
                    except Exception as e:
                        create_audit_log(
                            user=request.user, action='VIEW_DENIED_SIGNATURE_ERROR', dicom_file=dicom_file,
                            series=dicom_file.series, success=False,
                            error_message=f'Signature verification error: {str(e)}', request=request
                        )
                        return Response({'error': 'File integrity check failed'}, status=status.HTTP_403_FORBIDDEN)

            try:
                decrypted_data = _decrypt_dicom_file(dicom_file)
            except FileNotFoundError:
                return Response({'error': 'File not found on disk'}, status=status.HTTP_404_NOT_FOUND)
            except (ValueError, RuntimeError) as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f"Decryption failed: {e}")
                return Response({'error': 'Decryption failed', 'detail': str(e)},
                                 status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            decrypted_data = _ensure_uncompressed_dicom(decrypted_data)
            # NEW: real viewer metadata instead of frontend-side defaults.
            viewer_meta = get_dicom_viewer_metadata(decrypted_data)

            create_audit_log(user=request.user, action='VIEW', dicom_file=dicom_file,
                              series=dicom_file.series, success=True, request=request)

            response = HttpResponse(decrypted_data, content_type='application/dicom')
            response['Content-Disposition'] = f'inline; filename="{dicom_file.original_filename}"'
            response['X-Window-Width'] = str(viewer_meta.get('window_width', ''))
            response['X-Window-Center'] = str(viewer_meta.get('window_center', ''))
            response['X-Pixel-Spacing'] = str(viewer_meta.get('pixel_spacing', ''))
            response['X-Slice-Thickness'] = str(viewer_meta.get('slice_thickness', ''))
            response['X-Slice-Location'] = str(viewer_meta.get('slice_location', ''))
            response['X-Rows'] = str(viewer_meta.get('rows', ''))
            response['X-Columns'] = str(viewer_meta.get('columns', ''))
            # Browsers hide custom headers from JS unless explicitly exposed via CORS:
            response['Access-Control-Expose-Headers'] = (
                'X-Window-Width, X-Window-Center, X-Pixel-Spacing, '
                'X-Slice-Thickness, X-Slice-Location, X-Rows, X-Columns'
            )
            response['Cache-Control'] = 'no-store, no-cache, must-revalidate'
            response['Pragma'] = 'no-cache'
            return response

        except Exception as e:
            logger.error(f"View failed: {str(e)}", exc_info=True)
            create_audit_log(user=request.user, action='VIEW', success=False, error_message=str(e), request=request)
            return Response({'error': 'Failed to view file', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteDicomFileView(APIView):
    """Delete a DICOM file (Admin only)"""
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, file_id):
        if request.user.role != 'admin':
            return Response({'error': 'Only administrators can delete files'}, status=status.HTTP_403_FORBIDDEN)

        try:
            dicom_file = DicomFile.objects.get(id=file_id, is_deleted=False)
            dicom_file.is_deleted = True
            dicom_file.deleted_at = timezone.now()
            dicom_file.deleted_by = request.user
            dicom_file.save()

            dicom_file.encrypted_data = None
            dicom_file.save()

            create_audit_log(user=request.user, action='FILE_DELETED', dicom_file=dicom_file,
                              series=dicom_file.series, success=True, request=request)

            return Response({'message': 'File deleted successfully'}, status=status.HTTP_200_OK)

        except DicomFile.DoesNotExist:
            return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Delete failed: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


"""
Quantalock API views — Chunk 3 of N.

APPEND to the same api/views.py file. Add these imports alongside
the earlier chunks' imports:

    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from django.core.mail import EmailMessage
    from .serializers import PatientReportSerializer, GenerateReportSerializer

This chunk contains:
  - GenerateReportView   (extended: accepts series_id as the primary
    path, dicom_file_id kept as a legacy fallback; creates the report
    as status='draft' rather than immediately final)
  - SignReportView       (new — finalizes a draft report and applies
    a real ML-DSA-87 signature over its content for non-repudiation,
    matching the frontend's 'Sign (ML-DSA-87)' action)
  - ListReportsView
  - DownloadReportView
  - EmailReportView
"""

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from django.core.mail import EmailMessage

from .serializers import PatientReportSerializer, GenerateReportSerializer


def _report_subject(dicom_file, series):
    """Returns whichever of series/dicom_file this report is actually about."""
    return series if series else dicom_file


class GenerateReportView(APIView):
    """Generate a draft patient report, tied to a worklist order (series)."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if request.user.role not in ['admin', 'doctor', 'nurse', 'radiologist']:
            return Response({'error': 'Only clinical staff can generate reports'},
                             status=status.HTTP_403_FORBIDDEN)

        serializer = GenerateReportSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data

        series = None
        dicom_file = None

        if data.get('series_id'):
            try:
                series = DicomSeries.objects.get(id=data['series_id'])
            except DicomSeries.DoesNotExist:
                return Response({'error': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)
        elif data.get('dicom_file_id'):
            try:
                dicom_file = DicomFile.objects.get(id=data['dicom_file_id'], is_deleted=False)
            except DicomFile.DoesNotExist:
                return Response({'error': 'DICOM file not found'}, status=status.HTTP_404_NOT_FOUND)

        subject = _report_subject(dicom_file, series)

        try:
            report = PatientReport.objects.create(
                dicom_file=dicom_file,
                series=series,
                generated_by=request.user,
                clinical_history=data.get('clinical_history', ''),
                technique=data.get('technique', ''),
                findings=data['findings'],
                impression=data.get('impression', ''),
                recommendations=data.get('recommendations', ''),
                status='draft',
            )

            create_audit_log(
                user=request.user, action='REPORT_GENERATED', dicom_file=dicom_file, series=series,
                success=True, details=f"Draft report created for {subject.patient_name if subject else 'unknown'}",
                request=request
            )

            return Response({
                'message': 'Draft report created',
                'report': PatientReportSerializer(report).data
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SignReportView(APIView):
    """
    Finalize a draft report: locks it, timestamps it, and applies a
    real ML-DSA-87 signature over the report content using the
    signing radiologist's own per-user PQC key (from session — the
    same key material used to sign uploaded files). This is what
    gives the report non-repudiation, not just a status flag.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, report_id):
        if request.user.role not in ['admin', 'doctor', 'radiologist']:
            return Response({'error': 'Only physicians can sign reports'}, status=status.HTTP_403_FORBIDDEN)

        try:
            report = PatientReport.objects.get(id=report_id, is_deleted=False)
        except PatientReport.DoesNotExist:
            return Response({'error': 'Report not found'}, status=status.HTTP_404_NOT_FOUND)

        if report.status == 'finalized':
            return Response({'error': 'Report is already finalized'}, status=status.HTTP_400_BAD_REQUEST)

        pqc_sig_secret_key = request.session.get('pqc_sig_secret_key')
        if not pqc_sig_secret_key:
            return Response({'error': 'Signature key not available. Please logout and login again.'},
                             status=status.HTTP_401_UNAUTHORIZED)

        try:
            # Sign the report's actual clinical content, not just an ID —
            # so any tampering with findings/impression after signing is detectable.
            report_content = (
                f"{report.clinical_history}|{report.technique}|{report.findings}|"
                f"{report.impression}|{report.recommendations}"
            ).encode('utf-8')

            signature = pqc.sign_data(report_content, pqc_sig_secret_key)

            report.status = 'finalized'
            report.finalized_at = timezone.now()
            report.pqc_signature_hash = signature
            report.save()

            create_audit_log(
                user=request.user, action='REPORT_SIGNED_ML_DSA', dicom_file=report.dicom_file,
                series=report.series, success=True,
                details=f"Report finalized and ML-DSA-87 signed by {request.user.get_full_name()}",
                request=request
            )

            return Response({
                'message': 'Report finalized and signed',
                'report': PatientReportSerializer(report).data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Report signing failed: {e}")
            return Response({'error': 'Failed to sign report', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ListReportsView(APIView):
    """List all reports (role-based filtering)"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        if request.user.role in ['admin']:
            reports = PatientReport.objects.filter(is_deleted=False)
        else:
            reports = PatientReport.objects.filter(generated_by=request.user, is_deleted=False)

        status_filter = request.query_params.get('status')
        if status_filter and status_filter != 'all':
            reports = reports.filter(status=status_filter)

        reports = reports.order_by('-generated_at')
        serializer = PatientReportSerializer(reports, many=True)
        return Response(serializer.data)


def _build_report_pdf(report, request):
    """Shared PDF generation for download and (future) print flows."""
    subject = _report_subject(report.dicom_file, report.series)

    pdf_filename = f"{subject.patient_name.replace(' ', '_')}_{subject.modality or 'DICOM'}-Report_{report.generated_at.strftime('%Y-%m-%d')}.pdf"
    pdf_path = os.path.join(settings.REPORTS_DIR, pdf_filename)

    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24,
                                  textColor=colors.HexColor('#23395B'), spaceAfter=30,
                                  alignment=TA_CENTER, fontName='Helvetica-Bold')
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14,
                                    textColor=colors.HexColor('#23395B'), spaceAfter=12,
                                    fontName='Helvetica-Bold')
    normal_style = styles['Normal']

    story.append(Paragraph(settings.INSTITUTION_NAME, title_style))
    story.append(Paragraph('Post-Quantum Secured Diagnostic Imaging Report', styles['Normal']))
    story.append(Spacer(1, 0.5 * inch))

    accession = report.series.accession_number if report.series else 'N/A'
    study_date = subject.study_date.strftime('%B %d, %Y') if subject and subject.study_date else 'N/A'

    patient_data = [
        ['Patient Name:', subject.patient_name if subject else 'N/A'],
        ['Patient ID:', subject.patient_id if subject else 'N/A'],
        ['Accession Number:', accession],
        ['Study Type:', f"{subject.modality or 'DICOM'} Imaging" if subject else 'N/A'],
        ['Study Date:', study_date],
        ['Report Date:', report.generated_at.strftime('%B %d, %Y')],
        ['Reporting Physician:', report.generated_by.get_full_name() if report.generated_by else 'N/A'],
        ['Status:', 'FINALIZED — ML-DSA-87 Signed' if report.status == 'finalized' else 'DRAFT'],
    ]
    patient_table = Table(patient_data, colWidths=[2 * inch, 4 * inch])
    patient_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#FAFBFC')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#8EA8C3')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(patient_table)
    story.append(Spacer(1, 0.3 * inch))

    for label, value in [
        ('CLINICAL HISTORY', report.clinical_history),
        ('TECHNIQUE', report.technique),
        ('FINDINGS', report.findings),
        ('IMPRESSION', report.impression),
        ('RECOMMENDATIONS', report.recommendations),
    ]:
        if value:
            story.append(Paragraph(label, heading_style))
            story.append(Paragraph(value.replace('\n', '<br/>'), normal_style))
            story.append(Spacer(1, 0.2 * inch))

    if report.status == 'finalized':
        story.append(Spacer(1, 0.2 * inch))
        sig_style = ParagraphStyle('Sig', parent=styles['Normal'], fontSize=8,
                                    textColor=colors.HexColor('#0E5847'), fontName='Helvetica-Bold')
        story.append(Paragraph(
            f"Digitally signed (ML-DSA-87, NIST FIPS 204) — {report.finalized_at.strftime('%B %d, %Y %H:%M')}",
            sig_style
        ))

    story.append(Spacer(1, 0.3 * inch))
    confidential_style = ParagraphStyle('Confidential', parent=styles['Normal'], fontSize=9,
                                         textColor=colors.HexColor('#EF5350'), alignment=TA_CENTER,
                                         fontName='Helvetica-Bold')
    story.append(Paragraph('CONFIDENTIAL MEDICAL REPORT — For patient and authorized healthcare providers only',
                            confidential_style))

    doc.build(story)

    file_size = os.path.getsize(pdf_path)
    report.pdf_path = pdf_path
    report.file_size = file_size
    report.save()

    return pdf_path, pdf_filename


class DownloadReportView(APIView):
    """Download (or generate-on-demand) a report PDF"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, report_id):
        try:
            report = PatientReport.objects.get(id=report_id, is_deleted=False)

            if request.user.role not in ['admin'] and report.generated_by != request.user:
                return Response({'error': 'You can only download your own reports'},
                                 status=status.HTTP_403_FORBIDDEN)

            if not report.pdf_path or not os.path.exists(report.pdf_path):
                pdf_path, pdf_filename = _build_report_pdf(report, request)
            else:
                pdf_path = report.pdf_path
                pdf_filename = report.get_filename()

            create_audit_log(user=request.user, action='REPORT_DOWNLOADED', dicom_file=report.dicom_file,
                              series=report.series, success=True, request=request)

            with open(pdf_path, 'rb') as pdf_file:
                response = HttpResponse(pdf_file.read(), content_type='application/pdf')
                response['Content-Disposition'] = f'attachment; filename="{pdf_filename}"'
                return response

        except PatientReport.DoesNotExist:
            return Response({'error': 'Report not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Report download failed: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class EmailReportView(APIView):
    """Email an existing (or generate-on-demand) report"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, report_id):
        if request.user.role not in ['admin', 'doctor', 'nurse', 'radiologist']:
            return Response({'error': 'Only clinical staff can email reports'}, status=status.HTTP_403_FORBIDDEN)

        patient_email = request.data.get('patient_email')
        if not patient_email:
            return Response({'error': 'Patient email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            report = PatientReport.objects.get(id=report_id, is_deleted=False)
            subject = _report_subject(report.dicom_file, report.series)

            if not report.pdf_path or not os.path.exists(report.pdf_path):
                pdf_path, pdf_filename = _build_report_pdf(report, request)
            else:
                pdf_path = report.pdf_path
                pdf_filename = report.get_filename()

            email = EmailMessage(
                subject=f'Medical Imaging Report - {subject.patient_name if subject else ""}',
                body=(
                    f"Dear {subject.patient_name if subject else 'Patient'},\n\n"
                    f"Your medical imaging report from {settings.INSTITUTION_NAME} is attached.\n\n"
                    f"Report Date: {report.generated_at.strftime('%B %d, %Y')}\n\n"
                    f"This is a confidential medical document. Please keep it secure.\n\n"
                    f"{settings.INSTITUTION_NAME}\n{settings.INSTITUTION_PHONE}\n{settings.INSTITUTION_EMAIL}"
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[patient_email],
            )
            with open(pdf_path, 'rb') as pdf_file:
                email.attach(pdf_filename, pdf_file.read(), 'application/pdf')
            email.send(fail_silently=False)

            report.emailed_to = patient_email
            report.emailed_at = timezone.now()
            report.email_status = 'SENT'
            report.save()

            create_audit_log(user=request.user, action='REPORT_EMAILED', dicom_file=report.dicom_file,
                              series=report.series, success=True, request=request)

            return Response({'message': 'Report emailed successfully', 'emailed_to': patient_email})

        except PatientReport.DoesNotExist:
            return Response({'error': 'Report not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Failed to email report: {str(e)}")
            try:
                report.email_status = 'FAILED'
                report.save()
            except Exception:
                pass
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


"""
Quantalock API views — Chunk 4 of N.

APPEND to the same api/views.py file. Add these imports:

    import psutil
    from django.db.models import Count, Sum, Avg
    from django.db.models.functions import TruncDate, TruncMonth
    from django.core.cache import cache

This chunk contains:
  - DashboardStatsView (extended: now includes real order/worklist
    counts by review_status and priority — the old version only knew
    about files, it had no concept of orders at all)
  - SystemHealthView
"""

import psutil
from django.db.models import Count, Sum, Avg
from django.db.models.functions import TruncDate, TruncMonth
from django.core.cache import cache


class DashboardStatsView(APIView):
    """Get dashboard statistics"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        cache_key = f'dashboard_stats_{request.user.id}'
        cached_data = cache.get(cache_key)
        if cached_data:
            return Response(cached_data)

        try:
            now = timezone.now()
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            week_start = now - timedelta(days=7)
            month_start = now - timedelta(days=30)

            is_clinical = request.user.role in ['admin', 'doctor', 'nurse', 'radiologist']

            if is_clinical:
                files = DicomFile.objects.filter(is_deleted=False)
                orders = DicomSeries.objects.all()
                all_users = User.objects.filter(is_active=True)
                audit_logs = AuditLog.objects.all()
                reports = PatientReport.objects.filter(is_deleted=False)
            else:
                files = DicomFile.objects.filter(uploaded_by=request.user, is_deleted=False)
                orders = DicomSeries.objects.filter(uploaded_by=request.user)
                all_users = User.objects.filter(id=request.user.id)
                audit_logs = AuditLog.objects.filter(user=request.user)
                reports = PatientReport.objects.filter(generated_by=request.user, is_deleted=False)

            # === FILE STATS ===
            total_files = files.count()
            files_today = files.filter(uploaded_at__gte=today_start).count()
            files_this_week = files.filter(uploaded_at__gte=week_start).count()
            files_by_modality = list(files.values('modality').annotate(count=Count('id')).order_by('-count')[:5])
            files_by_tag = list(files.values('tag').annotate(count=Count('id')))
            total_storage_bytes = files.aggregate(total=Sum('file_size'))['total'] or 0

            recent_uploads = files.order_by('-uploaded_at')[:10]
            recent_uploads_data = [{
                'id': str(f.id), 'filename': f.original_filename, 'patient_name': f.patient_name,
                'modality': f.modality, 'size': f.file_size, 'uploaded_at': f.uploaded_at.isoformat(),
                'uploaded_by': f.uploaded_by.get_full_name() if f.uploaded_by else 'Unknown'
            } for f in recent_uploads]

            # === ORDER / WORKLIST STATS (new — the old system had no concept of orders) ===
            total_orders = orders.count()
            orders_by_status = list(orders.values('review_status').annotate(count=Count('id')))
            orders_by_priority = list(orders.values('priority').annotate(count=Count('id')))
            orders_pending = orders.filter(review_status='pending').count()
            orders_in_progress = orders.filter(review_status='in_progress').count()
            orders_urgent_or_stat = orders.filter(priority__in=['urgent', 'stat']).exclude(
                review_status='finalized'
            ).count()

            # === USER STATS ===
            total_users = all_users.count()
            users_by_role = list(all_users.values('role').annotate(count=Count('id')))
            active_users = all_users.filter(last_login__gte=month_start).count()

            # === AUDIT STATS ===
            total_actions = audit_logs.count()
            actions_today = audit_logs.filter(timestamp__gte=today_start).count()
            failed_actions_today = audit_logs.filter(success=False, timestamp__gte=today_start).count()

            if request.user.role in ['doctor', 'nurse', 'radiologist']:
                recent_activity = audit_logs.filter(
                    action__in=['UPLOAD', 'FILE_UPLOAD', 'DOWNLOAD', 'VIEW', 'REPORT_GENERATED',
                                'REPORT_SIGNED_ML_DSA', 'ORDER_CREATED', 'ORDER_STATUS_CHANGED']
                ).order_by('-timestamp')[:10]
            else:
                recent_activity = audit_logs.order_by('-timestamp')[:10]

            recent_activity_data = [{
                'id': str(log.id), 'user': log.user.get_full_name() if log.user else 'System',
                'action': log.action, 'success': log.success, 'timestamp': log.timestamp.isoformat(),
                'dicom_file': log.dicom_file.original_filename if log.dicom_file else None,
                'accession_number': log.series.accession_number if log.series else None,
            } for log in recent_activity]

            # === REPORT STATS ===
            total_reports = reports.count()
            reports_today = reports.filter(generated_at__gte=today_start).count()
            reports_draft = reports.filter(status='draft').count()
            reports_finalized = reports.filter(status='finalized').count()

            # === SYSTEM HEALTH SNAPSHOT ===
            cpu_percent = psutil.cpu_percent(interval=0.5)
            memory = psutil.virtual_memory()
            try:
                from django.db import connection
                connection.ensure_connection()
                db_status = 'healthy'
            except Exception:
                db_status = 'error'

            response_data = {
                'files': {
                    'total': total_files, 'today': files_today, 'this_week': files_this_week,
                    'by_modality': files_by_modality, 'by_tag': files_by_tag, 'recent': recent_uploads_data
                },
                'storage': {
                    'total_bytes': total_storage_bytes,
                    'total_gb': round(total_storage_bytes / (1024 ** 3), 2),
                    'files_count': total_files
                },
                'orders': {
                    'total': total_orders,
                    'by_status': orders_by_status,
                    'by_priority': orders_by_priority,
                    'pending': orders_pending,
                    'in_progress': orders_in_progress,
                    'urgent_or_stat_open': orders_urgent_or_stat,
                },
                'users': {'total': total_users, 'active': active_users, 'by_role': users_by_role},
                'activity': {
                    'total_actions': total_actions, 'actions_today': actions_today,
                    'failed_today': failed_actions_today, 'recent': recent_activity_data
                },
                'reports': {
                    'total': total_reports, 'today': reports_today,
                    'draft': reports_draft, 'finalized': reports_finalized
                },
                'system': {
                    'cpu_percent': cpu_percent, 'memory_percent': memory.percent, 'database_status': db_status
                },
                'generated_at': now.isoformat(),
                'user_role': request.user.role,
                'viewing_scope': 'institution' if is_clinical else 'personal'
            }

            # === UPLOAD TREND CHART ===
            period = request.query_params.get('period', '7')
            days_ago_map = {'7': 6, '30': 29, '90': 89}
            days_ago = days_ago_map.get(period, 6)
            date_format = '%b %d'
            start_date = now - timedelta(days=days_ago)

            daily_uploads = (
                files.filter(uploaded_at__gte=start_date)
                .annotate(date=TruncDate('uploaded_at'))
                .values('date')
                .annotate(count=Count('id'), volume_bytes=Sum('file_size'))
                .order_by('date')
            )
            uploads_dict = {item['date']: item for item in daily_uploads}

            upload_trends = []
            for i in range(days_ago + 1):
                d = (now - timedelta(days=days_ago - i)).date()
                _row = uploads_dict.get(d)
                upload_trends.append({
                    'date': d.strftime(date_format),
                    'uploads': _row['count'] if _row else 0,
                    'volume_bytes': (_row['volume_bytes'] or 0) if _row else 0,
                })

            response_data['upload_trends'] = upload_trends
            response_data['chart_period'] = period

        except Exception as e:
            logger.error(f"Dashboard stats failed: {str(e)}")
            return Response({'error': 'Failed to fetch dashboard statistics', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        cache.set(cache_key, response_data, 60)
        return Response(response_data, status=status.HTTP_200_OK)


class SystemHealthView(APIView):
    """System health metrics — admin/IT only"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            user_role = str(request.user.role).lower().strip()
            if user_role not in ['admin', 'it_support']:
                return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            total_files = DicomFile.objects.count()
            secured_files = DicomFile.objects.filter(
                encryption_algorithm='INSTITUTIONAL_PQC', pqc_encrypted=True
            ).count()
            success_rate = (secured_files / total_files * 100) if total_files > 0 else 100

            used_bytes = DicomFile.objects.aggregate(Sum('file_size'))['file_size__sum'] or 0
            used_gb = round(used_bytes / (1024 ** 3), 2)
            total_gb = 1000
            storage_percentage = (used_gb / total_gb * 100) if total_gb > 0 else 0

            avg_file_size_bytes = DicomFile.objects.aggregate(Avg('file_size'))['file_size__avg'] or 275000
            avg_file_size_mb = avg_file_size_bytes / (1024 * 1024)

            # Measured throughput figures from the dissertation's own
            # performance test suite — reused here as the basis for the
            # live estimate rather than re-deriving a new benchmark.
            aes_throughput_mb_s = 77
            aes_encryption_time_s = avg_file_size_mb / aes_throughput_mb_s
            pqc_overhead_s = (0.39 + 0.38) / 1000
            avg_encryption_time = round(aes_encryption_time_s + pqc_overhead_s, 3)
            pqc_decryption_overhead_s = (0.39 + 0.20) / 1000
            avg_decryption_time = round(aes_encryption_time_s + pqc_decryption_overhead_s, 3)

            recent_logs = AuditLog.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=1), success=True
            ).order_by('-timestamp')[:100]

            if recent_logs.count() > 10:
                logs_list = list(recent_logs)
                time_diffs = []
                for i in range(len(logs_list) - 1):
                    diff = (logs_list[i].timestamp - logs_list[i + 1].timestamp).total_seconds() * 1000
                    if 0 < diff < 5000:
                        time_diffs.append(diff)
                api_response_time = int(sum(time_diffs) / len(time_diffs)) if time_diffs else 156
            else:
                api_response_time = 156

            first_file = DicomFile.objects.order_by('uploaded_at').first()
            uptime_days = (timezone.now() - first_file.uploaded_at).days if first_file else 0

            last_24h = timezone.now() - timedelta(hours=24)
            failed_logins = AuditLog.objects.filter(action='FAILED_LOGIN', timestamp__gte=last_24h).count()
            active_users = User.objects.filter(last_login__gte=timezone.now() - timedelta(days=7),
                                                is_active=True).count()
            two_factor_enabled = User.objects.filter(two_factor_enabled=True).count()
            suspicious_activity = AuditLog.objects.filter(
                success=False, timestamp__gte=last_24h
            ).exclude(action='FAILED_LOGIN').count()

            recent_errors_qs = AuditLog.objects.filter(
                success=False, timestamp__gte=timezone.now() - timedelta(days=7)
            ).order_by('-timestamp')[:10]
            recent_errors = [{
                'id': str(log.id), 'type': log.action,
                'severity': 'error' if log.action in ['ENCRYPTION_FAILED', 'DECRYPTION_FAILED'] else 'warning',
                'message': log.error_message or f"{log.action} failed",
                'timestamp': log.timestamp.isoformat(),
                'user': log.user.username if log.user else 'System', 'resolved': False
            } for log in recent_errors_qs]

            return Response({
                'encryptionStatus': {
                    'total': total_files, 'secured': secured_files, 'failed': 0, 'processing': 0,
                    'successRate': round(success_rate, 2)
                },
                'storage': {
                    'total': total_gb, 'used': used_gb, 'available': total_gb - used_gb,
                    'percentage': round(storage_percentage, 2)
                },
                'performance': {
                    'avgEncryptionTime': avg_encryption_time, 'avgDecryptionTime': avg_decryption_time,
                    'apiResponseTime': api_response_time, 'uptime': uptime_days
                },
                'security': {
                    'activeUsers': active_users, 'twoFactorEnabled': two_factor_enabled,
                    'failedLogins': failed_logins, 'suspiciousActivity': suspicious_activity
                },
                'recentErrors': recent_errors
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"System health check failed: {str(e)}")
            return Response({'error': 'Failed to retrieve system health', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)



"""
Quantalock API views — Chunk 5 of N.

APPEND to the same api/views.py file. Add these imports:

    from django.contrib.auth.tokens import default_token_generator
    from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
    from django.utils.encoding import force_bytes, force_str
    from .serializers import UserSerializer

This chunk contains user administration, largely a direct port of the
original with role choices extended to include 'radiologist' and
worker_id prefixes adjusted to match:
  - ListUsersView
  - CreateUserView
  - UpdateUserView
  - DeleteUserView
  - GetUserView
"""

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from .serializers import UserSerializer


class ListUsersView(APIView):
    """List all users (Admin/IT Support only)"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            user_role = str(request.user.role).lower().strip()
            if user_role not in ['admin', 'it_support']:
                return Response({'error': 'Only administrators can view users'},
                                 status=status.HTTP_403_FORBIDDEN)

            users = User.objects.all().order_by('-date_joined')

            role = request.query_params.get('role')
            if role:
                users = users.filter(role=role.lower())

            is_active = request.query_params.get('is_active')
            if is_active is not None:
                users = users.filter(is_active=is_active.lower() == 'true')

            search = request.query_params.get('search')
            if search:
                users = users.filter(
                    Q(first_name__icontains=search) | Q(last_name__icontains=search) |
                    Q(email__icontains=search) | Q(username__icontains=search) |
                    Q(worker_id__icontains=search)
                )

            serializer = UserSerializer(users, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"List users failed: {str(e)}")
            return Response({'error': 'Failed to list users', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CreateUserView(APIView):
    """Create new user (Admin only)"""
    permission_classes = [permissions.IsAuthenticated]

    ROLE_PREFIXES = {
        'doctor': 'DOC',
        'radiologist': 'RAD',
        'nurse': 'NURSE',
        'it_support': 'IT',
        'admin': 'ADMIN',
    }

    def generate_worker_id(self, role):
        prefix = self.ROLE_PREFIXES.get(role, 'USER')
        existing_count = User.objects.filter(role=role).count()
        next_number = existing_count + 1
        if role == 'admin':
            return f"{prefix}-{next_number:02d}"
        return f"{prefix}{next_number:03d}"

    def check_role_limit(self, role):
        limits = {'admin': 2, 'it_support': 5}
        if role in limits:
            current_count = User.objects.filter(role=role).count()
            if current_count >= limits[role]:
                return False, f"Maximum {limits[role]} {role} users allowed"
        return True, None

    def post(self, request):
        try:
            user_role = str(request.user.role).lower().strip()
            if user_role not in ['admin', 'it_support']:
                return Response({'error': 'Permission denied. Only admins can create users.'},
                                 status=status.HTTP_403_FORBIDDEN)

            email = html.escape(request.data.get('email', '').strip())
            first_name = html.escape(request.data.get('first_name', '').strip())
            last_name = html.escape(request.data.get('last_name', '').strip())
            role = request.data.get('role', '').strip().lower()
            institution = request.data.get('institution', '').strip()
            phone_number = request.data.get('phone_number', '').strip()

            if not all([email, first_name, last_name, role]):
                return Response({'error': 'Email, first name, last name, and role are required'},
                                 status=status.HTTP_400_BAD_REQUEST)

            valid_roles = ['admin', 'doctor', 'radiologist', 'nurse', 'it_support']
            if role not in valid_roles:
                return Response({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'},
                                 status=status.HTTP_400_BAD_REQUEST)

            if User.objects.filter(email=email).exists():
                return Response({'error': 'A user with this email already exists'},
                                 status=status.HTTP_400_BAD_REQUEST)

            can_create, error_msg = self.check_role_limit(role)
            if not can_create:
                return Response({'error': error_msg}, status=status.HTTP_400_BAD_REQUEST)

            worker_id = self.generate_worker_id(role)
            username = worker_id
            counter = 1
            while User.objects.filter(Q(username=username) | Q(worker_id=worker_id)).exists():
                counter += 1
                prefix = self.ROLE_PREFIXES.get(role, 'USER')
                worker_id = f"{prefix}-{counter:02d}" if role == 'admin' else f"{prefix}{counter:03d}"
                username = worker_id

            temp_password = secrets.token_urlsafe(16)
            if request.data.get('password'):
                try:
                    validate_password_strength(request.data.get('password'))
                    temp_password = request.data.get('password')
                except ValidationError as e:
                    return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.create(
                username=username, email=email, first_name=first_name, last_name=last_name,
                worker_id=worker_id, role=role, institution=institution or request.user.institution,
                phone_number=phone_number, is_active=False, is_activated=False
            )
            user.set_password(temp_password)
            user.save()

            # === PQC keypair generation, encrypted with the temp password ===
            kem_keys = pqc.generate_kem_keypair()
            sig_keys = pqc.generate_sig_keypair()

            kem_encrypted = KeyEncryptionService.encrypt_key(kem_keys['secret_key'], temp_password)
            sig_encrypted = KeyEncryptionService.encrypt_key(sig_keys['secret_key'], temp_password)

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

            logger.info(f"Created user: {username} with role: {role}")

            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
            activation_link = f"{frontend_url}/activate/{uid}/{token}"
            logger.info(f'ACTIVATION LINK (copy-safe): {activation_link}')

            email_sent = False
            try:
                send_mail(
                    subject=f'Activate Your {settings.INSTITUTION_NAME} Account',
                    message=(
                        f"Dear {user.first_name} {user.last_name},\n\n"
                        f"Your account has been created by an administrator.\n\n"
                        f"Username: {user.username}\nWorker ID: {user.worker_id}\nEmail: {user.email}\n"
                        f"Role: {dict(User.ROLE_CHOICES).get(user.role, user.role)}\n\n"
                        f"Activate here: {activation_link}\n\nThis link expires in 24 hours.\n\n"
                        f"{settings.INSTITUTION_NAME} IT Team"
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
                email_sent = True
            except Exception as e:
                logger.error(f"Failed to send activation email to {user.email}: {str(e)}")

            create_audit_log(user=request.user, action='CREATE_USER', success=True, request=request)

            return Response({
                'message': 'User created successfully',
                'user': UserSerializer(user).data,
                'activation_link': activation_link,
                'email_sent': email_sent
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Create user failed: {str(e)}", exc_info=True)
            return Response({'error': 'Failed to create user', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateUserView(APIView):
    """Update a user (Admin only)"""
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, user_id):
        if request.user.role not in ['admin', 'it_support']:
            return Response({'error': 'Only administrators can update users'}, status=status.HTTP_403_FORBIDDEN)

        try:
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            if user.id == request.user.id:
                return Response({'error': 'Cannot update your own account through this endpoint'},
                                 status=status.HTTP_400_BAD_REQUEST)

            data = request.data

            if 'first_name' in data:
                user.first_name = data['first_name']
            if 'last_name' in data:
                user.last_name = data['last_name']
            if 'email' in data:
                if User.objects.filter(email=data['email']).exclude(id=user.id).exists():
                    return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
                user.email = data['email']
            if 'role' in data:
                valid_roles = ['admin', 'doctor', 'radiologist', 'nurse', 'it_support']
                if data['role'].lower() not in valid_roles:
                    return Response({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'},
                                     status=status.HTTP_400_BAD_REQUEST)
                user.role = data['role'].lower()
            if 'worker_id' in data:
                if User.objects.filter(worker_id=data['worker_id']).exclude(id=user.id).exists():
                    return Response({'error': 'Worker ID already exists'}, status=status.HTTP_400_BAD_REQUEST)
                user.worker_id = data['worker_id']
            if 'institution' in data:
                user.institution = data['institution']
            if 'phone_number' in data:
                user.phone_number = data['phone_number']
            if 'is_active' in data:
                user.is_active = data['is_active']

            # === Password reset with PQC key regeneration ===
            if data.get('password'):
                new_password = data['password']
                if len(new_password) < 8:
                    return Response({'error': 'Password must be at least 8 characters long'},
                                     status=status.HTTP_400_BAD_REQUEST)

                user.set_password(new_password)

                try:
                    kem_keys = pqc.generate_kem_keypair()
                    sig_keys = pqc.generate_sig_keypair()

                    kem_encrypted = KeyEncryptionService.encrypt_key(kem_keys['secret_key'], new_password)
                    sig_encrypted = KeyEncryptionService.encrypt_key(sig_keys['secret_key'], new_password)

                    user.pqc_kem_public_key = kem_keys['public_key']
                    user.pqc_kem_secret_key_encrypted = kem_encrypted['encrypted_key']
                    user.pqc_kem_secret_key_salt = kem_encrypted['salt']
                    user.pqc_kem_secret_key_nonce = kem_encrypted['nonce']

                    user.pqc_sig_public_key = sig_keys['public_key']
                    user.pqc_sig_secret_key_encrypted = sig_encrypted['encrypted_key']
                    user.pqc_sig_secret_key_salt = sig_encrypted['salt']
                    user.pqc_sig_secret_key_nonce = sig_encrypted['nonce']

                    user.pqc_enabled = True
                except Exception as e:
                    logger.error(f"Failed to regenerate PQC keys: {e}")
                    return Response({'error': 'Failed to regenerate encryption keys', 'detail': str(e)},
                                     status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                user.password_reset_required = True
                user.password_reset_at = timezone.now()

                try:
                    send_mail(
                        subject=f'Password Reset - {settings.INSTITUTION_NAME}',
                        message=(
                            f"Dear {user.first_name} {user.last_name},\n\n"
                            f"Your password has been reset by an administrator.\n\n"
                            f"Username: {user.username}\nTemporary Password: {new_password}\n\n"
                            f"You must change this password within 24 hours of your next login.\n\n"
                            f"If you did not request this, contact IT support immediately.\n\n"
                            f"{settings.INSTITUTION_NAME} IT Team"
                        ),
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        fail_silently=False,
                    )
                except Exception as e:
                    logger.error(f"Failed to send password reset email: {e}")

            user.save()

            create_audit_log(user=request.user, action='USER_UPDATED', success=True, request=request)

            return Response({
                'message': 'User updated successfully',
                'user': UserSerializer(user).data,
                'password_reset': 'password' in data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Update user failed: {str(e)}")
            return Response({'error': 'Failed to update user', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteUserView(APIView):
    """Delete user (Admin only)"""
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, user_id):
        try:
            if request.user.role not in ['admin', 'it_support']:
                create_audit_log(user=request.user, action='DELETE_USER_FAILED', success=False,
                                  error_message=f"Unauthorized delete attempt for user {user_id}", request=request)
                return Response({'error': 'Permission denied. Only admins can delete users.'},
                                 status=status.HTTP_403_FORBIDDEN)

            user_to_delete = User.objects.get(id=user_id)

            if user_to_delete.id == request.user.id:
                return Response({'error': 'You cannot delete your own account'}, status=status.HTTP_400_BAD_REQUEST)

            if user_to_delete.role == 'admin':
                if User.objects.filter(role='admin').count() <= 1:
                    return Response({'error': 'Cannot delete the last admin user'}, status=status.HTTP_400_BAD_REQUEST)

            username = user_to_delete.username
            user_to_delete.delete()

            create_audit_log(user=request.user, action='DELETE_USER', success=True, request=request)

            return Response({'message': f'User {username} deleted successfully'}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Delete user failed: {str(e)}")
            create_audit_log(user=request.user, action='DELETE_USER_FAILED', success=False,
                              error_message=str(e), request=request)
            return Response({'error': 'Failed to delete user', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetUserView(APIView):
    """Get a single user's details (Admin only)"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, user_id):
        if request.user.role != 'admin':
            return Response({'error': 'Only administrators can view user details'},
                             status=status.HTTP_403_FORBIDDEN)
        try:
            user = User.objects.get(id=user_id)
            return Response(UserSerializer(user).data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Get user failed: {str(e)}")
            return Response({'error': 'Failed to get user', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)



"""
Quantalock API views — Chunk 6 of N.

APPEND to the same api/views.py file. No new imports needed beyond
what chunks 1 and 5 already added.

Contains: ActivateAccountView, SetPasswordView, UpdateProfileView,
ChangePasswordView, UpdatePreferencesView, RegenerateUserKeysView,
ForcePasswordChangeView.
"""


class ActivateAccountView(APIView):
    """Verify activation token"""
    permission_classes = []

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                return Response({
                    'valid': True, 'email': user.email, 'first_name': user.first_name,
                    'last_name': user.last_name, 'worker_id': user.worker_id
                }, status=status.HTTP_200_OK)
            return Response({'valid': False, 'error': 'Invalid or expired activation link'},
                             status=status.HTTP_400_BAD_REQUEST)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'valid': False, 'error': 'Invalid activation link'},
                             status=status.HTTP_400_BAD_REQUEST)


class SetPasswordView(APIView):
    """Set password and activate account"""
    permission_classes = []

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)

            password = request.data.get('password')
            password_confirm = request.data.get('password_confirm')

            if not password or not password_confirm:
                return Response({'error': 'Both password fields are required'}, status=status.HTTP_400_BAD_REQUEST)
            if password != password_confirm:
                return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
            if len(password) < 8:
                return Response({'error': 'Password must be at least 8 characters long'},
                                 status=status.HTTP_400_BAD_REQUEST)
            if user.is_active and user.is_activated:
                return Response({'error': 'This account has already been activated. Please login.'},
                                 status=status.HTTP_400_BAD_REQUEST)
            if not default_token_generator.check_token(user, token):
                return Response({'error': 'Invalid or expired activation link.'}, status=status.HTTP_400_BAD_REQUEST)

            if user.pqc_kem_secret_key_encrypted:
                try:
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
                except Exception as e:
                    logger.error(f"Failed to re-encrypt PQC keys: {e}")

            user.set_password(password)
            user.is_active = True
            user.is_activated = True
            user.save()

            create_audit_log(user=user, action='ACCOUNT_ACTIVATED', success=True, request=request)

            try:
                send_mail(
                    subject=f'Welcome to {settings.INSTITUTION_NAME}',
                    message=(
                        f"Dear {user.first_name} {user.last_name},\n\nYour account is now active.\n\n"
                        f"Username: {user.username}\nWorker ID: {user.worker_id}\n\n"
                        f"{settings.INSTITUTION_NAME} Team"
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[user.email], fail_silently=True,
                )
            except Exception as e:
                logger.error(f"Failed to send welcome email: {str(e)}")

            return Response({
                'message': 'Account activated successfully! You can now log in.',
                'username': user.username, 'worker_id': user.worker_id, 'email': user.email
            }, status=status.HTTP_200_OK)

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid activation link'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Set password failed: {str(e)}")
            return Response({'error': 'Failed to activate account', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request):
        user = request.user
        try:
            user.first_name = request.data.get('firstName', user.first_name)
            user.last_name = request.data.get('lastName', user.last_name)
            user.email = request.data.get('email', user.email)
            user.phone_number = request.data.get('phoneNumber', user.phone_number)
            user.institution = request.data.get('institution', user.institution)
            if 'twoFactorEnabled' in request.data:
                user.two_factor_enabled = request.data.get('twoFactorEnabled')
            user.save()
            return Response({'message': 'Profile updated successfully', 'user': UserSerializer(user).data},
                             status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Profile update failed: {e}")
            return Response({'error': 'Failed to update profile'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get('currentPassword')
        new_password = request.data.get('newPassword')

        if not current_password or not new_password:
            return Response({'error': 'Current and new password required'}, status=status.HTTP_400_BAD_REQUEST)
        if not user.check_password(current_password):
            return Response({'error': 'Current password is incorrect'}, status=status.HTTP_403_FORBIDDEN)
        if len(new_password) < 8:
            return Response({'error': 'New password must be at least 8 characters'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Re-encrypt PQC keys under the new password so login still
            # decrypts them correctly afterward — the original file
            # skipped this, leaving keys unreadable after a self-service
            # password change.
            if user.pqc_kem_secret_key_encrypted:
                kem_secret = KeyEncryptionService.decrypt_key(
                    user.pqc_kem_secret_key_encrypted, user.pqc_kem_secret_key_salt,
                    user.pqc_kem_secret_key_nonce, current_password
                )
                sig_secret = KeyEncryptionService.decrypt_key(
                    user.pqc_sig_secret_key_encrypted, user.pqc_sig_secret_key_salt,
                    user.pqc_sig_secret_key_nonce, current_password
                )
                kem_re = KeyEncryptionService.encrypt_key(kem_secret, new_password)
                sig_re = KeyEncryptionService.encrypt_key(sig_secret, new_password)

                user.pqc_kem_secret_key_encrypted = kem_re['encrypted_key']
                user.pqc_kem_secret_key_salt = kem_re['salt']
                user.pqc_kem_secret_key_nonce = kem_re['nonce']

                user.pqc_sig_secret_key_encrypted = sig_re['encrypted_key']
                user.pqc_sig_secret_key_salt = sig_re['salt']
                user.pqc_sig_secret_key_nonce = sig_re['nonce']

            user.set_password(new_password)
            user.save()
            update_session_auth_hash(request, user)

            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Password change failed: {e}")
            return Response({'error': 'Failed to change password', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdatePreferencesView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        preference_type = request.data.get('type')
        preferences = request.data.get('preferences', {})

        try:
            if preference_type == 'notifications':
                user.notification_preferences = preferences
                user.save()
            elif preference_type == 'appearance':
                user.appearance_preferences = preferences
                user.save()
            else:
                return Response({'error': "type must be 'notifications' or 'appearance'"},
                                 status=status.HTTP_400_BAD_REQUEST)

            return Response({'message': f'{preference_type.capitalize()} preferences saved successfully'},
                             status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Preferences update failed: {e}")
            return Response({'error': 'Failed to save preferences'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RegenerateUserKeysView(APIView):
    """Admin endpoint to regenerate PQC keys for a user"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, user_id):
        if request.user.role != 'admin':
            return Response({'error': 'Only administrators can regenerate keys'}, status=status.HTTP_403_FORBIDDEN)

        try:
            user = User.objects.get(id=user_id)
            new_password = request.data.get('new_password')

            if not new_password:
                return Response({'error': 'new_password required'}, status=status.HTTP_400_BAD_REQUEST)
            if len(new_password) < 8:
                return Response({'error': 'Password must be at least 8 characters'}, status=status.HTTP_400_BAD_REQUEST)

            kem_keys = pqc.generate_kem_keypair()
            sig_keys = pqc.generate_sig_keypair()

            kem_encrypted = KeyEncryptionService.encrypt_key(kem_keys['secret_key'], new_password)
            sig_encrypted = KeyEncryptionService.encrypt_key(sig_keys['secret_key'], new_password)

            user.pqc_kem_public_key = kem_keys['public_key']
            user.pqc_kem_secret_key_encrypted = kem_encrypted['encrypted_key']
            user.pqc_kem_secret_key_salt = kem_encrypted['salt']
            user.pqc_kem_secret_key_nonce = kem_encrypted['nonce']

            user.pqc_sig_public_key = sig_keys['public_key']
            user.pqc_sig_secret_key_encrypted = sig_encrypted['encrypted_key']
            user.pqc_sig_secret_key_salt = sig_encrypted['salt']
            user.pqc_sig_secret_key_nonce = sig_encrypted['nonce']

            user.pqc_enabled = True
            user.set_password(new_password)
            user.save()

            create_audit_log(user=request.user, action='KEYS_REGENERATED', success=True, request=request)

            return Response({'message': f'Keys regenerated for {user.username}', 'username': user.username},
                             status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Key regeneration failed: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ForcePasswordChangeView(APIView):
    """User changes password after an admin reset"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        new_password_confirm = request.data.get('new_password_confirm')

        if not all([current_password, new_password, new_password_confirm]):
            return Response({'error': 'All fields required'}, status=status.HTTP_400_BAD_REQUEST)
        if new_password != new_password_confirm:
            return Response({'error': 'New passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        if len(new_password) < 8:
            return Response({'error': 'Password must be at least 8 characters'}, status=status.HTTP_400_BAD_REQUEST)
        if not request.user.check_password(current_password):
            return Response({'error': 'Current password is incorrect'}, status=status.HTTP_403_FORBIDDEN)

        try:
            request.user.set_password(new_password)

            kem_keys = pqc.generate_kem_keypair()
            sig_keys = pqc.generate_sig_keypair()

            kem_encrypted = KeyEncryptionService.encrypt_key(kem_keys['secret_key'], new_password)
            sig_encrypted = KeyEncryptionService.encrypt_key(sig_keys['secret_key'], new_password)

            request.user.pqc_kem_public_key = kem_keys['public_key']
            request.user.pqc_kem_secret_key_encrypted = kem_encrypted['encrypted_key']
            request.user.pqc_kem_secret_key_salt = kem_encrypted['salt']
            request.user.pqc_kem_secret_key_nonce = kem_encrypted['nonce']

            request.user.pqc_sig_public_key = sig_keys['public_key']
            request.user.pqc_sig_secret_key_encrypted = sig_encrypted['encrypted_key']
            request.user.pqc_sig_secret_key_salt = sig_encrypted['salt']
            request.user.pqc_sig_secret_key_nonce = sig_encrypted['nonce']

            request.user.password_reset_required = False
            request.user.password_reset_at = None
            request.user.save()

            update_session_auth_hash(request, request.user)

            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Password change failed: {e}")
            return Response({'error': 'Failed to change password'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



"""
Quantalock API views — Chunk 7 of N.

APPEND to the same api/views.py file. Add these imports:

    from api.cloud_storage_service import cloud_storage_service

Contains: CloudSyncView, SystemAlertsView, CloudSyncMonitorView,
ErrorRecoveryView, CloudStorageStatsView, NotificationsView,
CheckDuplicateView, UpdateMetadataView, GroupedFilesView.
"""

from api.cloud_storage_service import cloud_storage_service


class CloudSyncView(APIView):
    """Manual cloud sync for admins"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if request.user.role not in ['admin', 'it_support']:
            return Response({'error': 'Only administrators can trigger cloud sync'},
                             status=status.HTTP_403_FORBIDDEN)

        file_id = request.data.get('file_id')
        sync_all = request.data.get('sync_all', False)

        try:
            if sync_all:
                files_to_sync = DicomFile.objects.filter(is_deleted=False,
                                                          cloud_backup_status__in=['PENDING', 'FAILED'])
                success_count = fail_count = 0
                for dicom_file in files_to_sync:
                    result = self._sync_file_to_cloud(dicom_file, request.user)
                    if result['success']:
                        success_count += 1
                    else:
                        fail_count += 1
                return Response({'message': 'Bulk sync complete', 'total': files_to_sync.count(),
                                  'success': success_count, 'failed': fail_count}, status=status.HTTP_200_OK)
            else:
                dicom_file = DicomFile.objects.get(id=file_id, is_deleted=False)
                result = self._sync_file_to_cloud(dicom_file, request.user)
                if result['success']:
                    return Response({'message': 'File synced successfully', 'file_id': str(file_id),
                                      'azure': result.get('azure'), 'minio': result.get('minio')},
                                     status=status.HTTP_200_OK)
                return Response({'error': 'Sync failed', 'details': result.get('error')},
                                 status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except DicomFile.DoesNotExist:
            return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Cloud sync failed: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _sync_file_to_cloud(self, dicom_file, user):
        try:
            encrypted_file_path = os.path.join(settings.MEDIA_ROOT, dicom_file.file_path)
            if not os.path.exists(encrypted_file_path):
                return {'success': False, 'error': 'Encrypted file not found on disk'}

            blob_name = cloud_storage_service.get_cloud_path(dicom_file)
            backup_result = cloud_storage_service.upload_file(
                local_path=encrypted_file_path, blob_name=blob_name,
                metadata={'patient_id': dicom_file.patient_id, 'patient_name': dicom_file.patient_name,
                          'modality': dicom_file.modality, 'synced_by': user.username,
                          'synced_at': timezone.now().isoformat()}
            )

            if backup_result['success']:
                dicom_file.cloud_backup_status = 'SYNCED'
                dicom_file.last_successful_backup = timezone.now()
                if backup_result.get('azure') and 'error' not in backup_result['azure']:
                    dicom_file.azure_blob_name = blob_name
                if backup_result.get('minio') and 'error' not in backup_result['minio']:
                    dicom_file.minio_object_name = blob_name
                dicom_file.backup_error = None
            else:
                dicom_file.cloud_backup_status = 'FAILED'
                dicom_file.backup_error = str(backup_result)

            dicom_file.last_backup_attempt = timezone.now()
            dicom_file.save()
            return backup_result
        except Exception as e:
            logger.error(f"Sync failed for {dicom_file.id}: {e}")
            return {'success': False, 'error': str(e)}


class SystemAlertsView(APIView):
    """System alerts for IT Support"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            user_role = str(request.user.role).lower().strip()
            if user_role not in ['admin', 'it_support']:
                return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            now = timezone.now()
            last_24h = now - timedelta(hours=24)
            last_7d = now - timedelta(days=7)

            signature_failures = AuditLog.objects.filter(
                action__in=['VIEW_DENIED_INVALID_SIGNATURE', 'VIEW_WITH_FAILED_SIGNATURE'],
                timestamp__gte=last_7d
            ).order_by('-timestamp')[:20]
            signature_alerts = [{
                'id': str(log.id), 'type': 'signature_failure', 'severity': 'critical',
                'title': 'File Signature Verification Failed',
                'message': 'File signature invalid — possible key rotation or tampering',
                'file': log.dicom_file.original_filename if log.dicom_file else 'Unknown',
                'file_id': str(log.dicom_file.id) if log.dicom_file else None,
                'user': log.user.username if log.user else 'Unknown',
                'timestamp': log.timestamp.isoformat(), 'resolved': False, 'action_required': 'BULK_RESIGN'
            } for log in signature_failures]

            encryption_failures = AuditLog.objects.filter(
                action__in=['ENCRYPTION_FAILED', 'UPLOAD'], success=False, timestamp__gte=last_7d
            ).exclude(action='FAILED_LOGIN').order_by('-timestamp')[:20]
            encryption_alerts = [{
                'id': str(log.id), 'type': 'encryption_failure', 'severity': 'critical',
                'title': 'File Encryption Failed', 'message': log.error_message or 'Encryption process failed',
                'user': log.user.username if log.user else 'Unknown',
                'file': log.dicom_file.original_filename if log.dicom_file else 'Unknown',
                'timestamp': log.timestamp.isoformat(), 'resolved': False
            } for log in encryption_failures]

            sync_failures = DicomFile.objects.filter(
                cloud_backup_status='FAILED', last_backup_attempt__gte=last_7d, is_deleted=False
            ).order_by('-last_backup_attempt')[:20]
            sync_alerts = [{
                'id': str(f.id), 'type': 'cloud_sync_failure', 'severity': 'warning',
                'title': 'Cloud Backup Failed', 'message': f.backup_error or 'Failed to sync to cloud',
                'file': f.original_filename, 'patient': f.patient_name,
                'size': f"{f.file_size / (1024*1024):.2f} MB",
                'last_attempt': f.last_backup_attempt.isoformat() if f.last_backup_attempt else None,
                'timestamp': (f.last_backup_attempt or f.uploaded_at).isoformat(), 'resolved': False
            } for f in sync_failures]

            security_qs = AuditLog.objects.filter(success=False, timestamp__gte=last_24h).exclude(
                action='FAILED_LOGIN'
            ).order_by('-timestamp')[:10]
            security_alerts = [{
                'id': str(log.id), 'type': 'security_alert',
                'severity': 'critical' if log.action in ['VIEW_DENIED_INVALID_SIGNATURE'] else 'warning',
                'title': log.action, 'message': log.error_message or f"{log.action} failed",
                'user': log.user.username if log.user else 'Unknown', 'ip_address': log.ip_address,
                'timestamp': log.timestamp.isoformat(), 'resolved': False
            } for log in security_qs]

            pending_sync = DicomFile.objects.filter(
                cloud_backup_status='PENDING', uploaded_at__lte=now - timedelta(minutes=5), is_deleted=False
            ).count()
            pending_alerts = []
            if pending_sync > 0:
                pending_alerts.append({
                    'id': 'pending_sync', 'type': 'pending_sync', 'severity': 'info',
                    'title': 'Files Awaiting Cloud Sync',
                    'message': f'{pending_sync} file(s) pending cloud sync for over 5 minutes',
                    'count': pending_sync, 'timestamp': now.isoformat(), 'resolved': False
                })

            total_alerts = len(encryption_alerts) + len(sync_alerts) + len(security_alerts) + len(pending_alerts)
            critical_count = sum(1 for a in encryption_alerts + sync_alerts + security_alerts
                                  if a.get('severity') == 'critical')
            warning_count = sum(1 for a in encryption_alerts + sync_alerts + security_alerts
                                 if a.get('severity') == 'warning')

            return Response({
                'summary': {'total': total_alerts, 'critical': critical_count, 'warning': warning_count,
                            'info': len(pending_alerts)},
                'alerts': {'encryption': encryption_alerts, 'signature_failures': signature_alerts,
                          'cloud_sync': sync_alerts, 'security': security_alerts, 'pending': pending_alerts},
                'generated_at': now.isoformat()
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"System alerts failed: {e}")
            return Response({'error': 'Failed to fetch alerts', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CloudSyncMonitorView(APIView):
    """Monitor cloud sync status for all files"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            user_role = str(request.user.role).lower().strip()
            if user_role not in ['admin', 'it_support']:
                return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            status_filter = request.query_params.get('status')
            search = request.query_params.get('search')

            files = DicomFile.objects.filter(is_deleted=False)
            if status_filter:
                files = files.filter(cloud_backup_status=status_filter.upper())
            if search:
                files = files.filter(
                    Q(original_filename__icontains=search) | Q(patient_name__icontains=search) |
                    Q(patient_id__icontains=search)
                )
            files = files.order_by('-uploaded_at')

            from django.core.paginator import Paginator
            paginator = Paginator(files, 50)
            page_obj = paginator.get_page(request.query_params.get('page', 1))

            files_data = [{
                'id': str(f.id), 'filename': f.original_filename, 'patient_name': f.patient_name,
                'patient_id': f.patient_id, 'modality': f.modality, 'size': f.file_size,
                'size_mb': f"{f.file_size / (1024*1024):.2f}", 'uploaded_at': f.uploaded_at.isoformat(),
                'uploaded_by': f.uploaded_by.username if f.uploaded_by else 'Unknown',
                'cloud_status': f.cloud_backup_status,
                'last_attempt': f.last_backup_attempt.isoformat() if f.last_backup_attempt else None,
                'last_success': f.last_successful_backup.isoformat() if f.last_successful_backup else None,
                'error': f.backup_error, 'azure_synced': bool(f.azure_blob_name),
                'minio_synced': bool(f.minio_object_name)
            } for f in page_obj]

            total_files = DicomFile.objects.filter(is_deleted=False).count()
            synced = DicomFile.objects.filter(cloud_backup_status='SYNCED', is_deleted=False).count()
            pending = DicomFile.objects.filter(cloud_backup_status='PENDING', is_deleted=False).count()
            failed = DicomFile.objects.filter(cloud_backup_status='FAILED', is_deleted=False).count()

            return Response({
                'summary': {'total': total_files, 'synced': synced, 'pending': pending, 'failed': failed,
                            'success_rate': round((synced / total_files * 100), 2) if total_files > 0 else 100},
                'files': files_data,
                'pagination': {'current_page': page_obj.number, 'total_pages': paginator.num_pages,
                               'has_next': page_obj.has_next(), 'has_previous': page_obj.has_previous()}
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Cloud sync monitor failed: {e}")
            return Response({'error': 'Failed to fetch sync status', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ErrorRecoveryView(APIView):
    """View and recover from failed operations"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            user_role = str(request.user.role).lower().strip()
            if user_role not in ['admin', 'it_support']:
                return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            failed_uploads = AuditLog.objects.filter(
                action='UPLOAD', success=False, timestamp__gte=timezone.now() - timedelta(days=30)
            ).order_by('-timestamp')[:50]
            failed_uploads_data = [{
                'id': str(log.id), 'type': 'failed_upload', 'user': log.user.username if log.user else 'Unknown',
                'error': log.error_message, 'timestamp': log.timestamp.isoformat(),
                'ip_address': log.ip_address, 'recoverable': False
            } for log in failed_uploads]

            failed_syncs = DicomFile.objects.filter(cloud_backup_status='FAILED', is_deleted=False).order_by(
                '-last_backup_attempt'
            )[:50]
            failed_syncs_data = [{
                'id': str(f.id), 'type': 'failed_sync', 'filename': f.original_filename,
                'patient_name': f.patient_name, 'size_mb': f"{f.file_size / (1024*1024):.2f}",
                'error': f.backup_error,
                'last_attempt': f.last_backup_attempt.isoformat() if f.last_backup_attempt else None,
                'uploaded_at': f.uploaded_at.isoformat(), 'recoverable': True
            } for f in failed_syncs]

            failed_decryptions = AuditLog.objects.filter(
                action__in=['VIEW', 'DOWNLOAD'], success=False, timestamp__gte=timezone.now() - timedelta(days=7)
            ).order_by('-timestamp')[:30]
            failed_decryptions_data = [{
                'id': str(log.id), 'type': 'failed_decryption',
                'file': log.dicom_file.original_filename if log.dicom_file else 'Unknown',
                'user': log.user.username if log.user else 'Unknown', 'error': log.error_message,
                'timestamp': log.timestamp.isoformat(), 'recoverable': False
            } for log in failed_decryptions]

            return Response({
                'summary': {
                    'failed_uploads': len(failed_uploads_data), 'failed_syncs': len(failed_syncs_data),
                    'failed_decryptions': len(failed_decryptions_data),
                    'total_errors': len(failed_uploads_data) + len(failed_syncs_data) + len(failed_decryptions_data)
                },
                'errors': {'uploads': failed_uploads_data, 'cloud_syncs': failed_syncs_data,
                          'decryptions': failed_decryptions_data}
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error recovery view failed: {e}")
            return Response({'error': 'Failed to fetch errors', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CloudStorageStatsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            user_role = str(request.user.role).lower().strip()
            if user_role not in ['admin', 'it_support']:
                return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            total_bytes = DicomFile.objects.filter(is_deleted=False, cloud_backup_status='SYNCED').aggregate(
                total=Sum('file_size'))['total'] or 0
            total_gb = total_bytes / (1024 ** 3)

            total_blobs = DicomFile.objects.filter(is_deleted=False, cloud_backup_status='SYNCED').count()
            azure_blobs = DicomFile.objects.filter(azure_blob_name__isnull=False, is_deleted=False).count()
            minio_blobs = DicomFile.objects.filter(minio_object_name__isnull=False, is_deleted=False).count()

            total_capacity_gb = getattr(settings, 'CLOUD_STORAGE_CAPACITY_GB', 3000)
            usage_percent = (total_gb / total_capacity_gb * 100) if total_capacity_gb > 0 else 0

            return Response({
                'storage': {'used_bytes': total_bytes, 'used_gb': round(total_gb, 2),
                           'total_capacity_gb': total_capacity_gb,
                           'available_gb': round(total_capacity_gb - total_gb, 2),
                           'usage_percent': round(usage_percent, 2)},
                'blobs': {'total': total_blobs, 'azure': azure_blobs, 'minio': minio_blobs},
                'status': 'healthy' if usage_percent < 80 else 'warning' if usage_percent < 90 else 'critical'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Cloud storage stats failed: {e}")
            return Response({'error': 'Failed to fetch cloud storage stats', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class NotificationsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            user_role = str(request.user.role).lower().strip()
            now = timezone.now()
            last_24h = now - timedelta(hours=24)
            notifications = []

            if user_role in ['admin', 'it_support']:
                sig_failures = AuditLog.objects.filter(
                    action='VIEW_DENIED_INVALID_SIGNATURE', timestamp__gte=last_24h
                ).values('dicom_file').distinct().count()
                if sig_failures > 0:
                    notifications.append({
                        'id': 'signature_verification_failed', 'type': 'critical',
                        'title': 'File Signature Verification Failures',
                        'message': f'{sig_failures} file(s) failed signature verification in last 24h.',
                        'timestamp': now.isoformat(), 'link': '/security',
                        'action': 'BULK_RESIGN_REQUIRED', 'count': sig_failures
                    })

            if user_role == 'admin':
                failed_encryptions = AuditLog.objects.filter(
                    action='UPLOAD', success=False, timestamp__gte=last_24h).count()
                if failed_encryptions > 0:
                    notifications.append({
                        'id': 'failed_encryption', 'type': 'critical', 'title': 'PQC Encryption Failures',
                        'message': f'{failed_encryptions} file(s) failed PQC encryption',
                        'timestamp': now.isoformat(), 'link': '/it/error-recovery'
                    })
                failed_syncs = DicomFile.objects.filter(
                    cloud_backup_status='FAILED', last_backup_attempt__gte=last_24h, is_deleted=False).count()
                if failed_syncs > 0:
                    notifications.append({
                        'id': 'failed_sync_escalated', 'type': 'warning',
                        'title': 'Cloud Sync Failures (Escalated)',
                        'message': f'{failed_syncs} file(s) failed cloud sync after multiple retries',
                        'timestamp': now.isoformat(), 'link': '/it/sync-monitor'
                    })

            if user_role in ['admin', 'it_support']:
                pending_syncs = DicomFile.objects.filter(
                    cloud_backup_status='PENDING', uploaded_at__lte=now - timedelta(minutes=5),
                    is_deleted=False).count()
                if pending_syncs > 0:
                    notifications.append({
                        'id': 'pending_sync', 'type': 'info', 'title': 'Pending Cloud Syncs',
                        'message': f'{pending_syncs} file(s) awaiting cloud sync for >5 minutes',
                        'timestamp': now.isoformat(), 'link': '/it/sync-monitor'
                    })

            notifications = sorted(notifications, key=lambda x: x['timestamp'], reverse=True)[:20]
            return Response({
                'count': min(len(notifications), 20),
                'notifications': notifications,
                'grouped': {
                    'critical': [n for n in notifications if n['type'] == 'critical'],
                    'warning': [n for n in notifications if n['type'] == 'warning'],
                    'info': [n for n in notifications if n['type'] == 'info']
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Notifications failed: {e}")
            return Response({'error': 'Failed to fetch notifications'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CheckDuplicateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        patient_id = request.query_params.get('patient_id')
        study_date = request.query_params.get('study_date')
        modality = request.query_params.get('modality')

        if not all([patient_id, study_date, modality]):
            return Response({'error': 'Missing required parameters'}, status=status.HTTP_400_BAD_REQUEST)

        existing_files = DicomFile.objects.filter(
            patient_id=patient_id, study_date=study_date, modality=modality, is_deleted=False)

        if existing_files.exists():
            return Response({
                'is_duplicate': True,
                'existing_files': [{
                    'id': str(f.id), 'patient_name': f.patient_name, 'modality': f.modality,
                    'uploaded_at': f.uploaded_at.isoformat(), 'uploaded_by': f.uploaded_by.username
                } for f in existing_files]
            }, status=status.HTTP_200_OK)

        return Response({'is_duplicate': False, 'existing_files': []}, status=status.HTTP_200_OK)


class UpdateMetadataView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, file_id):
        if request.user.role not in ['admin', 'doctor']:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

        try:
            dicom_file = DicomFile.objects.get(id=file_id, is_deleted=False)
        except DicomFile.DoesNotExist:
            return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)

        for field in ['condition', 'body_region', 'study_description', 'referring_doctor', 'tag']:
            if field in request.data:
                setattr(dicom_file, field, request.data[field])
        dicom_file.save()

        create_audit_log(user=request.user, action='METADATA_UPDATE', dicom_file=dicom_file,
                          series=dicom_file.series, success=True, request=request)

        return Response({'message': 'Metadata updated successfully', 'file': DicomFileSerializer(dicom_file).data},
                         status=status.HTTP_200_OK)


class GroupedFilesView(APIView):
    """Files grouped by patient / study / series"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            if request.user.role not in ['admin', 'doctor', 'nurse', 'radiologist']:
                files = DicomFile.objects.filter(uploaded_by=request.user, is_deleted=False)
            else:
                files = DicomFile.objects.filter(is_deleted=False)

            search = request.query_params.get('search', '').strip()
            if search:
                files = files.filter(
                    Q(patient_name__icontains=search) | Q(patient_id__icontains=search) |
                    Q(modality__icontains=search) | Q(study_description__icontains=search)
                )

            patients = {}
            for file in files:
                patient_key = file.patient_id or 'UNKNOWN'
                if patient_key not in patients:
                    patients[patient_key] = {
                        'patient_id': file.patient_id, 'patient_name': file.patient_name, 'studies': {}
                    }
                study_key = f"{file.study_date}_{file.modality}"
                if study_key not in patients[patient_key]['studies']:
                    patients[patient_key]['studies'][study_key] = {
                        'study_date': file.study_date.isoformat() if file.study_date else None,
                        'modality': file.modality, 'study_description': file.study_description, 'series': {}
                    }
                series_key = file.series_uid or f"single_{file.id}"
                if series_key not in patients[patient_key]['studies'][study_key]['series']:
                    patients[patient_key]['studies'][study_key]['series'][series_key] = {
                        'series_uid': file.series_uid, 'series_description': file.series_description,
                        'series_number': file.series_number, 'is_series': file.is_part_of_series,
                        'files': [], 'file_count': 0, 'total_size': 0,
                        'uploaded_at': file.uploaded_at.isoformat(),
                        'uploaded_by': file.uploaded_by.username if file.uploaded_by else 'Unknown',
                        'cloud_status': file.cloud_backup_status, 'first_file_id': None
                    }
                series = patients[patient_key]['studies'][study_key]['series'][series_key]
                series['files'].append({
                    'id': str(file.id), 'filename': file.original_filename,
                    'instance_number': file.instance_number, 'size': file.file_size
                })
                series['file_count'] += 1
                series['total_size'] += file.file_size
                if not series['first_file_id']:
                    series['first_file_id'] = str(file.id)
                series['files'].sort(key=lambda x: int(x['instance_number']) if x['instance_number'] else 0)

            patients_list = []
            for patient_id, patient_data in patients.items():
                studies_list = []
                for study_key, study_data in patient_data['studies'].items():
                    study_data['series'] = list(study_data['series'].values())
                    studies_list.append(study_data)
                patient_data['studies'] = studies_list
                patients_list.append(patient_data)

            patients_list.sort(
                key=lambda x: x['studies'][0]['series'][0]['uploaded_at'] if x['studies'] and x['studies'][0]['series'] else '',
                reverse=True
            )

            return Response({'patients': patients_list, 'total_patients': len(patients_list),
                              'total_files': files.count()}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Grouped files view failed: {str(e)}")
            return Response({'error': 'Failed to fetch grouped files', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)



"""
Quantalock API views — Chunk 8 of N (final view chunk).

APPEND to the same api/views.py file. Add this import:

    from .serializers import AuditLogSerializer

cloud_storage_service is already imported in chunk 7, no need to
reimport. pqc, cache, User, DicomFile, AuditLog, KeyEncryptionService,
match_token, login, timezone, ExpiringToken are all already imported
in chunk 1.

Contains views missing from earlier chunks but required by urls.py:
  - AuditLogView       (never built earlier, urls.py imports it)
  - Verify2FAView      (never built earlier, urls.py imports it —
    completes login for accounts that answered LoginView's
    requires_2fa prompt, re-authenticating with username/password/
    totp_code and finishing the same session key-decrypt + token
    issuance LoginView does)

Plus the Security Dashboard chunk proper:
  - BulkResignFilesView   (admin re-signs files whose signature no
    longer verifies against their uploader's current public key —
    re-signs with the ADMIN's own current session sig key and
    reattributes uploaded_by to the admin, since that's the only key
    material available without the original uploader's password)
  - SecurityDashboardView (signature integrity + 2FA adoption +
    recent resign/failure activity, audit-log-driven rather than
    re-verifying every file live)
  - DeleteInvalidFilesView (admin purges files that failed
    verification and were not resigned)
  - RecoverableFilesView   (soft-deleted files that still have a
    successful cloud backup)
  - RecoverFromCloudView / BulkRecoverFromCloudView (restore those
    files from Azure/MinIO back onto local disk and undelete them)
"""

from .serializers import AuditLogSerializer


class AuditLogView(APIView):
    """List audit log entries (role-based filtering)"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            user_role = str(request.user.role).lower().strip()
            if user_role in ['admin', 'it_support']:
                logs = AuditLog.objects.all()
            else:
                logs = AuditLog.objects.filter(user=request.user)

            action = request.query_params.get('action')
            if action:
                logs = logs.filter(action=action)

            success_param = request.query_params.get('success')
            if success_param is not None:
                logs = logs.filter(success=success_param.lower() == 'true')

            search = request.query_params.get('search')
            if search:
                logs = logs.filter(
                    Q(details__icontains=search) |
                    Q(error_message__icontains=search) |
                    Q(user__username__icontains=search)
                )

            from django.core.paginator import Paginator
            logs = logs.order_by('-timestamp')
            paginator = Paginator(logs, 100)
            page_obj = paginator.get_page(request.query_params.get('page', 1))

            serializer = AuditLogSerializer(page_obj, many=True)
            return Response({
                'results': serializer.data,
                'pagination': {
                    'current_page': page_obj.number,
                    'total_pages': paginator.num_pages,
                    'total_count': paginator.count,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous(),
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Audit log fetch failed: {str(e)}")
            return Response({'error': 'Failed to fetch audit logs', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Verify2FAView(APIView):
    """
    Completes login for a user who received requires_2fa from
    LoginView. Frontend resends username/password (needed again here
    to decrypt the session PQC keys) plus the TOTP code.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        totp_code = request.data.get('totp_code')

        if not all([username, password, totp_code]):
            return Response({'error': 'Username, password, and totp_code are required'},
                             status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request=request, username=username, password=password)
        if not user:
            create_audit_log(user=None, action='FAILED_LOGIN', success=False,
                              error_message=f'Failed 2FA-verify login for username: {username}', request=request)
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.two_factor_enabled:
            return Response({'error': '2FA is not enabled for this account'}, status=status.HTTP_400_BAD_REQUEST)

        if not match_token(user, totp_code):
            create_audit_log(user=user, action='FAILED_2FA', success=False,
                              error_message='Invalid 2FA code', request=request)
            return Response({'error': 'Invalid 2FA code', 'requires_2fa': True},
                             status=status.HTTP_403_FORBIDDEN)

        request.session['2fa_verified_at'] = timezone.now().isoformat()
        request.session['2fa_verified'] = True

        ExpiringToken.objects.filter(user=user).delete()
        token = ExpiringToken.objects.create(user=user)

        login(request, user)

        try:
            if user.pqc_kem_secret_key_encrypted and user.pqc_sig_secret_key_encrypted:
                kem_secret_key = KeyEncryptionService.decrypt_key(
                    user.pqc_kem_secret_key_encrypted, user.pqc_kem_secret_key_salt,
                    user.pqc_kem_secret_key_nonce, password
                )
                sig_secret_key = KeyEncryptionService.decrypt_key(
                    user.pqc_sig_secret_key_encrypted, user.pqc_sig_secret_key_salt,
                    user.pqc_sig_secret_key_nonce, password
                )
                request.session['pqc_kem_secret_key'] = kem_secret_key
                request.session['pqc_sig_secret_key'] = sig_secret_key
                request.session.set_expiry(28800)
        except Exception as e:
            logger.error(f"Failed to decrypt PQC keys during 2FA verify: {str(e)}")

        create_audit_log(user=user, action='LOGIN', success=True, details='via 2FA verify', request=request)

        return Response({
            'token': token.key,
            'expires_in': token.time_remaining,
            'user': {
                'id': str(user.id), 'username': user.username, 'role': user.role,
                'is_staff': user.is_staff, 'is_superuser': user.is_superuser,
            },
            'two_factor_enabled': True
        }, status=status.HTTP_200_OK)


class BulkResignFilesView(APIView):
    """
    Re-sign files whose PQC signature no longer verifies against their
    uploader's current public key (stale after a key rotation or
    password reset). Requires the admin's own password to confirm
    intent and unlock their session sig key if not already present.
    Files are re-signed with the ADMIN's current key and reattributed
    to them, since the original uploader's password isn't available
    here to re-derive their key.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if request.user.role != 'admin':
            create_audit_log(user=request.user, action='UNAUTHORIZED_RESIGN_ATTEMPT', success=False,
                              error_message='Non-admin attempted bulk resign', request=request)
            return Response({'error': 'Only administrators can bulk re-sign files'},
                             status=status.HTTP_403_FORBIDDEN)

        rate_key = f'bulk_resign_{request.user.id}'
        if cache.get(rate_key):
            create_audit_log(user=request.user, action='RESIGN_RATE_LIMITED', success=False,
                              error_message='Bulk resign attempted before cooldown elapsed', request=request)
            return Response({'error': 'Please wait before running bulk re-sign again'},
                             status=status.HTTP_429_TOO_MANY_REQUESTS)

        password = request.data.get('password')
        if not password:
            return Response({'error': 'Password confirmation required'}, status=status.HTTP_400_BAD_REQUEST)
        if not request.user.check_password(password):
            create_audit_log(user=request.user, action='FAILED_RESIGN_PASSWORD', success=False,
                              error_message='Incorrect password on bulk resign attempt', request=request)
            return Response({'error': 'Incorrect password'}, status=status.HTTP_403_FORBIDDEN)

        admin_sig_secret_key = request.session.get('pqc_sig_secret_key')
        if not admin_sig_secret_key:
            try:
                admin_sig_secret_key = KeyEncryptionService.decrypt_key(
                    request.user.pqc_sig_secret_key_encrypted, request.user.pqc_sig_secret_key_salt,
                    request.user.pqc_sig_secret_key_nonce, password
                )
            except Exception as e:
                logger.error(f"Failed to unlock admin sig key for bulk resign: {e}")
                return Response({'error': 'Failed to unlock signing key'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        cache.set(rate_key, True, 60)

        candidate_files = DicomFile.objects.filter(is_deleted=False, pqc_signature__isnull=False)
        resigned = []
        failed = []

        for dicom_file in candidate_files:
            try:
                if not dicom_file.encrypted_data:
                    continue

                encrypted_data = dicom_file.encrypted_data

                uploader = dicom_file.uploaded_by
                is_valid = False
                if uploader and uploader.pqc_sig_public_key:
                    try:
                        is_valid = pqc.verify_signature(encrypted_data, dicom_file.pqc_signature,
                                                          uploader.pqc_sig_public_key)
                    except Exception:
                        is_valid = False

                if is_valid:
                    continue

                new_signature = pqc.sign_data(encrypted_data, admin_sig_secret_key)
                dicom_file.pqc_signature = new_signature
                dicom_file.uploaded_by = request.user
                dicom_file.save()
                resigned.append(str(dicom_file.id))

            except Exception as e:
                logger.error(f"Resign failed for {dicom_file.id}: {e}")
                failed.append(str(dicom_file.id))

        create_audit_log(
            user=request.user, action='BULK_RESIGN_FILES', success=True,
            details=f"Resigned {len(resigned)} file(s), {len(failed)} failed", request=request
        )
        if failed:
            create_audit_log(
                user=request.user, action='BULK_RESIGN_FAILED', success=False,
                error_message=f"{len(failed)} file(s) could not be resigned", request=request
            )

        return Response({
            'message': f'Re-signed {len(resigned)} file(s)',
            'resigned': resigned,
            'failed': failed,
        }, status=status.HTTP_200_OK)


class SecurityDashboardView(APIView):
    """
    Security overview: signature integrity, 2FA adoption, recent
    resign activity and recent signature failures. Driven by audit
    logs rather than re-verifying every file live on every request,
    the same pattern SystemAlertsView already uses.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            user_role = str(request.user.role).lower().strip()
            if user_role not in ['admin', 'it_support']:
                return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

            now = timezone.now()
            last_30d = now - timedelta(days=30)

            total_signed = DicomFile.objects.filter(is_deleted=False, pqc_signature__isnull=False).count()

            failing_file_ids = set(
                AuditLog.objects.filter(
                    action__in=['VIEW_DENIED_INVALID_SIGNATURE', 'VIEW_WITH_FAILED_SIGNATURE'],
                    timestamp__gte=last_30d, dicom_file__isnull=False
                ).values_list('dicom_file_id', flat=True).distinct()
            )
            still_invalid = DicomFile.objects.filter(
                id__in=failing_file_ids, is_deleted=False
            )
            still_invalid_count = 0
            for f in still_invalid:
                uploader = f.uploaded_by
                if not uploader or not uploader.pqc_sig_public_key:
                    still_invalid_count += 1
                    continue
                if not f.encrypted_data:
                    continue
                data = f.encrypted_data
                try:
                    if not pqc.verify_signature(data, f.pqc_signature, uploader.pqc_sig_public_key):
                        still_invalid_count += 1
                except Exception:
                    still_invalid_count += 1

            total_users = User.objects.filter(is_active=True).count()
            users_2fa = User.objects.filter(is_active=True, two_factor_enabled=True).count()

            recent_resigns = AuditLog.objects.filter(
                action='BULK_RESIGN_FILES', timestamp__gte=last_30d
            ).order_by('-timestamp')[:10]
            recent_resigns_data = [{
                'id': str(log.id), 'admin': log.user.username if log.user else 'Unknown',
                'details': log.details, 'timestamp': log.timestamp.isoformat()
            } for log in recent_resigns]

            recent_failures = AuditLog.objects.filter(
                action__in=['VIEW_DENIED_INVALID_SIGNATURE', 'VIEW_WITH_FAILED_SIGNATURE'],
                timestamp__gte=last_30d
            ).order_by('-timestamp')[:10]
            recent_failures_data = [{
                'id': str(log.id), 'file': log.dicom_file.original_filename if log.dicom_file else 'Unknown',
                'user': log.user.username if log.user else 'Unknown', 'timestamp': log.timestamp.isoformat()
            } for log in recent_failures]

            return Response({
                'signature_integrity': {
                    'total_signed_files': total_signed,
                    'currently_invalid': still_invalid_count,
                    'valid': total_signed - still_invalid_count,
                    'integrity_rate': round(((total_signed - still_invalid_count) / total_signed * 100), 2)
                                       if total_signed > 0 else 100
                },
                'two_factor_adoption': {
                    'total_active_users': total_users, 'with_2fa': users_2fa,
                    'adoption_rate': round((users_2fa / total_users * 100), 2) if total_users > 0 else 0
                },
                'recent_resigns': recent_resigns_data,
                'recent_signature_failures': recent_failures_data,
                'generated_at': now.isoformat(),
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Security dashboard failed: {e}")
            return Response({'error': 'Failed to fetch security dashboard', 'detail': str(e)},
                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteInvalidFilesView(APIView):
    """Admin purges files that failed signature verification and were not resigned"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if request.user.role != 'admin':
            return Response({'error': 'Only administrators can delete invalid files'},
                             status=status.HTTP_403_FORBIDDEN)

        file_ids = request.data.get('file_ids', [])
        if not file_ids:
            return Response({'error': 'file_ids is required'}, status=status.HTTP_400_BAD_REQUEST)

        deleted = []
        for file_id in file_ids:
            try:
                dicom_file = DicomFile.objects.get(id=file_id, is_deleted=False)

                uploader = dicom_file.uploaded_by
                is_valid = False
                if uploader and uploader.pqc_sig_public_key and dicom_file.pqc_signature:
                    if dicom_file.encrypted_data:
                        data = dicom_file.encrypted_data
                        try:
                            is_valid = pqc.verify_signature(data, dicom_file.pqc_signature, uploader.pqc_sig_public_key)
                        except Exception:
                            is_valid = False

                if is_valid:
                    continue

                dicom_file.is_deleted = True
                dicom_file.deleted_at = timezone.now()
                dicom_file.deleted_by = request.user
                dicom_file.save()

                dicom_file.encrypted_data = None
                dicom_file.save()

                create_audit_log(user=request.user, action='FILE_DELETED_INVALID_SIGNATURE', dicom_file=dicom_file,
                                  series=dicom_file.series, success=True, request=request)
                deleted.append(str(dicom_file.id))

            except DicomFile.DoesNotExist:
                continue
            except Exception as e:
                logger.error(f"Delete invalid file {file_id} failed: {e}")
                continue

        return Response({'message': f'Deleted {len(deleted)} invalid file(s)', 'deleted': deleted},
                         status=status.HTTP_200_OK)


class RecoverableFilesView(APIView):
    """Soft-deleted files that still have a successful cloud backup"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user_role = str(request.user.role).lower().strip()
        if user_role not in ['admin', 'it_support']:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

        files = DicomFile.objects.filter(
            is_deleted=True
        ).exclude(azure_blob_name__isnull=True, minio_object_name__isnull=True).order_by('-deleted_at')

        files_data = [{
            'id': str(f.id), 'filename': f.original_filename, 'patient_name': f.patient_name,
            'patient_id': f.patient_id, 'modality': f.modality,
            'deleted_at': f.deleted_at.isoformat() if f.deleted_at else None,
            'deleted_by': f.deleted_by.username if f.deleted_by else 'Unknown',
            'azure_available': bool(f.azure_blob_name), 'minio_available': bool(f.minio_object_name),
            'last_successful_backup': f.last_successful_backup.isoformat() if f.last_successful_backup else None,
        } for f in files]

        return Response({'count': len(files_data), 'files': files_data}, status=status.HTTP_200_OK)


def _recover_file_from_cloud(dicom_file, user, request):
    """Shared recovery logic for single and bulk recovery."""
    blob_name = dicom_file.azure_blob_name or dicom_file.minio_object_name
    if not blob_name:
        return {'success': False, 'error': 'No cloud backup reference for this file'}

    local_path = os.path.join(settings.MEDIA_ROOT, dicom_file.file_path)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)

    # result = cloud_storage_service.download_file(blob_name=blob_name, local_path=local_path)
    result = cloud_storage_service.download_file(blob_name=blob_name, destination_path=local_path)
    if not result.get('success'):
        return result

    dicom_file.is_deleted = False
    dicom_file.deleted_at = None
    dicom_file.deleted_by = None
    dicom_file.save()

    create_audit_log(user=user, action='FILE_RECOVERED_FROM_CLOUD', dicom_file=dicom_file,
                      series=dicom_file.series, success=True, request=request)
    return {'success': True}


class RecoverFromCloudView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user_role = str(request.user.role).lower().strip()
        if user_role not in ['admin', 'it_support']:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

        file_id = request.data.get('file_id')
        if not file_id:
            return Response({'error': 'file_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            dicom_file = DicomFile.objects.get(id=file_id, is_deleted=True)
        except DicomFile.DoesNotExist:
            return Response({'error': 'Deleted file not found'}, status=status.HTTP_404_NOT_FOUND)

        result = _recover_file_from_cloud(dicom_file, request.user, request)
        if result['success']:
            return Response({'message': 'File recovered successfully', 'file_id': str(dicom_file.id)},
                             status=status.HTTP_200_OK)
        return Response({'error': 'Recovery failed', 'detail': result.get('error')},
                         status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BulkRecoverFromCloudView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user_role = str(request.user.role).lower().strip()
        if user_role not in ['admin', 'it_support']:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

        file_ids = request.data.get('file_ids')
        if file_ids:
            files = DicomFile.objects.filter(id__in=file_ids, is_deleted=True)
        else:
            files = DicomFile.objects.filter(is_deleted=True).exclude(
                azure_blob_name__isnull=True, minio_object_name__isnull=True
            )

        recovered = []
        failed = []
        for dicom_file in files:
            result = _recover_file_from_cloud(dicom_file, request.user, request)
            if result['success']:
                recovered.append(str(dicom_file.id))
            else:
                failed.append({'id': str(dicom_file.id), 'error': result.get('error')})

        return Response({
            'message': f'Recovered {len(recovered)} file(s), {len(failed)} failed',
            'recovered': recovered, 'failed': failed,
        }, status=status.HTTP_200_OK)






