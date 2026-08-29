from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework.authtoken.models import Token as DefaultToken
from datetime import timedelta
from django.utils import timezone
import uuid


class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('doctor', 'Doctor'),
        ('nurse', 'Nurse'),
        ('it_support', 'IT Support'),
        ('radiologist', 'Radiologist'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='nurse')
    worker_id = models.CharField(max_length=50, unique=True)
    institution = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20, blank=True)

    # 2FA
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_secret = models.CharField(max_length=32, blank=True)
    two_factor_setup_complete = models.BooleanField(default=False)

    # Preferences
    notification_preferences = models.JSONField(default=dict, blank=True)
    appearance_preferences = models.JSONField(default=dict, blank=True)

    # Account activation
    is_activated = models.BooleanField(default=False)
    activation_token = models.CharField(max_length=100, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Per-user PQC keys (encrypted secret keys, used for signing/attribution)
    pqc_kem_secret_key_encrypted = models.TextField(blank=True, null=True)
    pqc_kem_secret_key_salt = models.TextField(blank=True, null=True)
    pqc_kem_secret_key_nonce = models.TextField(blank=True, null=True)

    pqc_sig_secret_key_encrypted = models.TextField(blank=True, null=True)
    pqc_sig_secret_key_salt = models.TextField(blank=True, null=True)
    pqc_sig_secret_key_nonce = models.TextField(blank=True, null=True)

    # Public keys stay unencrypted
    pqc_kem_public_key = models.TextField(blank=True, null=True)
    pqc_sig_public_key = models.TextField(blank=True, null=True)

    # Password reset tracking
    password_reset_required = models.BooleanField(default=False)
    password_reset_at = models.DateTimeField(null=True, blank=True)

    pqc_enabled = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['worker_id']),
            models.Index(fields=['role']),
        ]

    def __str__(self):
        return f"{self.get_full_name()} ({self.role})"

    @property
    def badge_color(self):
        colors = {
            'admin': '#0E5847',
            'doctor': '#406E8E',
            'radiologist': '#406E8E',
            'nurse': '#F5A623',
            'it_support': '#8EA8C3',
        }
        return colors.get(self.role, '#8EA8C3')


class DicomSeries(models.Model):
    """
    A radiology order / worklist item AND the DICOM series it's attached to.
    Extended beyond the original file-grouping model to carry RIS fields,
    so the worklist has one real, queryable source instead of a separate
    Order table duplicating patient/study data.
    """

    PRIORITY_CHOICES = [
        ('routine', 'Routine'),
        ('urgent', 'Urgent'),
        ('stat', 'STAT'),
    ]

    REVIEW_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('finalized', 'Finalized'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    series_instance_uid = models.CharField(max_length=255, unique=True, blank=True, null=True)

    # Patient / study identity
    patient_id = models.CharField(max_length=100)
    patient_name = models.CharField(max_length=255)
    patient_dob = models.DateField(null=True, blank=True)
    modality = models.CharField(max_length=50)
    body_part = models.CharField(max_length=100, blank=True)
    study_date = models.DateField(null=True, blank=True)
    series_description = models.CharField(max_length=255, blank=True)

    # RIS worklist fields
    accession_number = models.CharField(max_length=50, unique=True)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='routine')
    review_status = models.CharField(max_length=20, choices=REVIEW_STATUS_CHOICES, default='pending')
    referring_physician = models.CharField(max_length=255, blank=True)
    clinical_indication = models.TextField(blank=True)
    assigned_radiologist = models.ForeignKey(
        'User', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='assigned_series'
    )
    order_created_at = models.DateTimeField(auto_now_add=True)

    # Series/file metadata
    total_slices = models.IntegerField(default=0)
    uploaded_slices = models.IntegerField(default=0)

    cloud_backup_status = models.CharField(
        max_length=20,
        choices=[
            ('PENDING', 'Pending'),
            ('SYNCED', 'Synced'),
            ('PARTIAL', 'Partial'),
            ('FAILED', 'Failed'),
        ],
        default='PENDING'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_series')

    class Meta:
        db_table = 'dicom_series'
        verbose_name = 'DICOM Series'
        verbose_name_plural = 'DICOM Series'
        ordering = ['-order_created_at']
        indexes = [
            models.Index(fields=['accession_number']),
            models.Index(fields=['review_status']),
            models.Index(fields=['priority']),
            models.Index(fields=['patient_id']),
        ]

    def __str__(self):
        return f"{self.accession_number} - {self.patient_name} ({self.modality})"


class DicomFile(models.Model):
    """Stores DICOM file metadata and encryption information"""

    TAG_CHOICES = [
        ('URGENT', 'Urgent'),
        ('ROUTINE', 'Routine'),
        ('FOLLOW_UP', 'Follow-up'),
        ('ARCHIVED', 'Archived'),
    ]

    ENCRYPTION_ALGORITHM_CHOICES = [
        ('LEGACY_AES', 'Legacy AES-256'),
        ('INSTITUTIONAL_PQC', 'Institutional PQC Hybrid'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    original_filename = models.CharField(max_length=255)
    file_size = models.BigIntegerField(help_text="Size in bytes")
    content_type = models.CharField(max_length=100, default="application/dicom")
    file_path = models.CharField(max_length=500, help_text="Local file path (legacy, being phased out)", blank=True)
    encrypted_data = models.BinaryField(null=True, blank=True, help_text="Encrypted DICOM bytes stored directly in DB")

    study_instance_uid = models.CharField(max_length=255, blank=True, default='')
    series_instance_uid = models.CharField(max_length=255, blank=True, default='')
    series_description = models.CharField(max_length=255, blank=True, default='')
    series_number = models.CharField(max_length=50, blank=True, default='')
    is_part_of_series = models.BooleanField(default=False)
    series_uid = models.CharField(max_length=255, blank=True, null=True, db_index=True)
    date_of_birth = models.DateField(blank=True, null=True)
    condition = models.CharField(max_length=255, blank=True)
    body_region = models.CharField(max_length=100, blank=True)
    referring_doctor = models.CharField(max_length=255, blank=True)

    aes_key = models.BinaryField(help_text="AES-256 key (protected by PQC if pqc_encrypted=True)")
    iv = models.BinaryField(help_text="Initialization vector for AES")
    encryption_algorithm = models.CharField(
        max_length=50, default='LEGACY_AES', choices=ENCRYPTION_ALGORITHM_CHOICES
    )

    pqc_encrypted = models.BooleanField(default=False)
    pqc_encapsulated_key = models.TextField(blank=True, null=True)
    pqc_protected_key = models.TextField(blank=True, null=True)
    pqc_signature = models.TextField(blank=True, null=True)
    encrypted_for_user = models.ForeignKey(
        'User', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='pqc_encrypted_files'
    )
    encrypted_with_key_version = models.IntegerField(default=1)
    institutional_encrypted_fek = models.TextField(blank=True, null=True)
    institutional_protected_key = models.TextField(blank=True, null=True)

    patient_id = models.CharField(max_length=100, blank=True)
    patient_name = models.CharField(max_length=255, blank=True)
    study_date = models.DateField(blank=True, null=True)
    study_description = models.TextField(blank=True)
    modality = models.CharField(max_length=20, blank=True)
    institution_name = models.CharField(max_length=255, blank=True)

    tag = models.CharField(max_length=20, choices=TAG_CHOICES, default='ROUTINE')
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_files')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    series = models.ForeignKey(
        DicomSeries, on_delete=models.CASCADE, related_name='files',
        null=True, blank=True
    )
    instance_number = models.IntegerField(null=True, blank=True)

    cloud_backup_status = models.CharField(
        max_length=20,
        choices=[
            ('PENDING', 'Pending Backup'),
            ('SYNCED', 'Synced to Cloud'),
            ('FAILED', 'Backup Failed'),
            ('PARTIAL', 'Partially Synced'),
        ],
        default='PENDING'
    )
    azure_blob_name = models.CharField(max_length=500, blank=True, null=True)
    minio_object_name = models.CharField(max_length=500, blank=True, null=True)
    last_backup_attempt = models.DateTimeField(null=True, blank=True)
    last_successful_backup = models.DateTimeField(null=True, blank=True)
    backup_error = models.TextField(blank=True, null=True)

    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='deleted_files'
    )

    class Meta:
        db_table = 'dicom_files'
        ordering = ['-uploaded_at']
        indexes = [
            models.Index(fields=['uploaded_by', '-uploaded_at']),
            models.Index(fields=['patient_id']),
            models.Index(fields=['modality']),
            models.Index(fields=['tag']),
        ]

    def __str__(self):
        return f"{self.original_filename} - {self.patient_name}"


class AuditLog(models.Model):
    """HIPAA-compliant audit trail for all file access"""

    ACTION_CHOICES = [
        ('REGISTER', 'User Registered'),
        ('UPLOAD', 'File Uploaded'),
        ('VIEW', 'File Viewed'),
        ('METADATA_UPDATE', 'Metadata Update'),
        ('DOWNLOAD', 'File Downloaded'),
        ('DELETE', 'File Deleted'),
        ('UPDATE', 'Metadata Updated'),
        ('LOGIN', 'User Login'),
        ('LOGOUT', 'User Logout'),
        ('FAILED_LOGIN', 'Failed Login Attempt'),
        ('ENCRYPTION_SUCCESS', 'Encryption Successful'),
        ('ENCRYPTION_FAILED', 'Encryption Failed'),
        ('DECRYPTION_SUCCESS', 'Decryption Successful'),
        ('DECRYPTION_FAILED', 'Decryption Failed'),
        ('FAILED_2FA', 'Failed 2FA Attempt'),
        ('FILE_UPLOAD', 'File Upload'),
        ('FILE_DELETED', 'File Deleted'),
        ('FILE_DELETED_INVALID_SIGNATURE', 'File Deleted — Invalid Signature'),
        ('FILE_RECOVERED_FROM_CLOUD', 'File Recovered from Cloud'),
        ('REPORT_GENERATED', 'Report Generated'),
        ('REPORT_EMAILED', 'Report Emailed'),
        ('REPORT_DOWNLOADED', 'Report Downloaded'),
        ('CREATE_USER', 'User Created'),
        ('USER_UPDATED', 'User Updated'),
        ('DELETE_USER', 'User Deleted'),
        ('DELETE_USER_FAILED', 'User Deletion Failed'),
        ('ACCOUNT_ACTIVATED', 'Account Activated'),
        ('KEYS_REGENERATED', 'PQC Keys Regenerated'),
        ('BULK_RESIGN_FILES', 'Bulk File Re-sign'),
        ('BULK_RESIGN_FAILED', 'Bulk File Re-sign Failed'),
        ('UNAUTHORIZED_RESIGN_ATTEMPT', 'Unauthorized Re-sign Attempt'),
        ('FAILED_RESIGN_PASSWORD', 'Failed Re-sign Password Verification'),
        ('RESIGN_RATE_LIMITED', 'Re-sign Rate Limited'),
        ('VIEW_RATE_LIMITED', 'View Rate Limited'),
        ('VIEW_DENIED', 'View Denied'),
        ('VIEW_DENIED_INVALID_SIGNATURE', 'View Denied — Invalid Signature'),
        ('VIEW_DENIED_SIGNATURE_ERROR', 'View Denied — Signature Error'),
        ('VIEW_WITH_FAILED_SIGNATURE', 'Viewed With Failed Signature'),
        # RIS worklist actions, new for Quantalock
        ('ORDER_CREATED', 'Radiology Order Created'),
        ('ORDER_STATUS_CHANGED', 'Order Status Changed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    dicom_file = models.ForeignKey(
        DicomFile, on_delete=models.CASCADE, related_name='audit_logs',
        null=True, blank=True
    )
    series = models.ForeignKey(
        DicomSeries, on_delete=models.CASCADE, related_name='audit_logs',
        null=True, blank=True
    )

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()

    timestamp = models.DateTimeField(auto_now_add=True)

    success = models.BooleanField(default=True)
    details = models.TextField(blank=True, default='')
    error_message = models.TextField(blank=True, null=True)
    additional_info = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['-timestamp']),
        ]

    def __str__(self):
        file_info = f" on {self.dicom_file.original_filename}" if self.dicom_file else ""
        return f"{self.action}{file_info} by {self.user} at {self.timestamp}"


class UserConsent(models.Model):
    """GDPR-compliant consent management"""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='consent')
    data_processing_consent = models.BooleanField(default=False)
    data_storage_consent = models.BooleanField(default=False)
    terms_accepted = models.BooleanField(default=False)
    consent_given_at = models.DateTimeField(auto_now_add=True)
    consent_updated_at = models.DateTimeField(auto_now=True)
    ip_address = models.GenericIPAddressField()

    def __str__(self):
        return f"Consent for {self.user.username}"


class PatientReport(models.Model):
    """Generated patient / radiology reports"""

    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('finalized', 'Finalized'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    dicom_file = models.ForeignKey(DicomFile, on_delete=models.CASCADE, related_name='reports', null=True, blank=True)
    series = models.ForeignKey(DicomSeries, on_delete=models.CASCADE, related_name='reports', null=True, blank=True)
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='generated_reports')
    generated_at = models.DateTimeField(auto_now_add=True)

    clinical_history = models.TextField(blank=True)
    technique = models.TextField(blank=True)
    findings = models.TextField(help_text="Clinical findings from image review")
    impression = models.TextField(blank=True, help_text="Clinical impression/diagnosis")
    recommendations = models.TextField(blank=True)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    finalized_at = models.DateTimeField(null=True, blank=True)

    # ML-DSA-87 signature over the finalized report content, for non-repudiation
    pqc_signature_hash = models.TextField(blank=True, null=True)

    pdf_path = models.CharField(max_length=500, blank=True)
    file_size = models.BigIntegerField(default=0)

    emailed_to = models.EmailField(blank=True, null=True)
    emailed_at = models.DateTimeField(blank=True, null=True)
    email_status = models.CharField(
        max_length=20,
        choices=[
            ('NOT_SENT', 'Not Sent'),
            ('SENT', 'Sent Successfully'),
            ('FAILED', 'Failed to Send'),
            ('BOUNCED', 'Bounced'),
        ],
        default='NOT_SENT'
    )

    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'patient_reports'
        ordering = ['-generated_at']

    def __str__(self):
        subject = self.series.patient_name if self.series else (self.dicom_file.patient_name if self.dicom_file else 'Unknown')
        return f"Report for {subject} - {self.generated_at.date()}"

    def get_filename(self):
        subject = self.series if self.series else self.dicom_file
        patient_name = subject.patient_name.replace(' ', '_')
        modality = subject.modality or 'DICOM'
        date = self.generated_at.strftime('%Y-%m-%d')
        return f"{patient_name}_{modality}-Report_{date}.pdf"


class Institution(models.Model):
    """Institution-level master keys for file encryption"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)

    pqc_kem_public_key = models.TextField(help_text="ML-KEM-1024 public key")
    pqc_kem_secret_key_encrypted = models.TextField(help_text="ML-KEM-1024 secret key, encrypted")
    pqc_kem_secret_key_salt = models.CharField(max_length=64, blank=True, null=True)
    pqc_kem_secret_key_nonce = models.CharField(max_length=32, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    key_version = models.IntegerField(default=1)
    is_active = models.BooleanField(default=True)

    rotated_at = models.DateTimeField(null=True, blank=True)
    rotated_by = models.ForeignKey(
        'User', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='rotated_keys'
    )
    rotation_reason = models.TextField(blank=True, null=True)

    recovery_metadata = models.TextField(blank=True, null=True)

    pqc_algorithm_version = models.CharField(
        max_length=50, default='ML-KEM-1024_v1+ML-DSA-87_v1'
    )
    algorithm_updated_at = models.DateTimeField(null=True, blank=True)

    replaced_by = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='previous_version'
    )

    class Meta:
        db_table = 'institutions'
        ordering = ['-key_version']
        constraints = [
            models.UniqueConstraint(
                fields=['name'],
                condition=models.Q(is_active=True),
                name='unique_active_institution'
            )
        ]

    def __str__(self):
        status = "ACTIVE" if self.is_active else "ARCHIVED"
        return f"{self.name} v{self.key_version} ({status})"


class ExpiringToken(DefaultToken):
    """Token that expires after 30 minutes"""

    class Meta:
        proxy = True

    def is_expired(self):
        if not self.created:
            return True
        return timezone.now() > self.created + timedelta(minutes=30)

    @property
    def expires_at(self):
        return self.created + timedelta(minutes=30)

    @property
    def time_remaining(self):
        if self.is_expired():
            return 0
        remaining = (self.expires_at - timezone.now()).total_seconds()
        return max(0, int(remaining))