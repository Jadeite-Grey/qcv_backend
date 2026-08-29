from rest_framework import serializers
from .models import User, DicomFile, DicomSeries, AuditLog, UserConsent, PatientReport


class UserSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    pqc_key_fingerprint = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'name',
            'worker_id',
            'role',
            'institution',
            'phone_number',
            'is_activated',
            'is_active',
            'status',
            'two_factor_enabled',
            'pqc_key_fingerprint',
            'date_joined',
            'last_login',
        ]
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def get_name(self, obj):
        return obj.get_full_name() or obj.username

    def get_status(self, obj):
        return 'active' if obj.is_active else 'inactive'

    def get_pqc_key_fingerprint(self, obj):
        # Short display fingerprint derived from the public signature key,
        # not the key itself, never expose secret material here.
        if obj.pqc_sig_public_key:
            return f"0x{obj.pqc_sig_public_key[:48]}"
        return None


class DicomFileSerializer(serializers.ModelSerializer):
    uploaded_by_name = serializers.CharField(source='uploaded_by.get_full_name', read_only=True)
    uploaded_by_role = serializers.CharField(source='uploaded_by.role', read_only=True)
    series_accession_number = serializers.CharField(source='series.accession_number', read_only=True, default=None)

    class Meta:
        model = DicomFile
        fields = [
            'id',
            'original_filename',
            'file_size',
            'file_path',
            'patient_id',
            'patient_name',
            'date_of_birth',
            'study_date',
            'study_description',
            'modality',
            'institution_name',
            'condition',
            'body_region',
            'referring_doctor',
            'series',
            'series_accession_number',
            'series_description',
            'series_number',
            'instance_number',
            'tag',
            'uploaded_by',
            'uploaded_by_name',
            'uploaded_by_role',
            'uploaded_at',
            'is_deleted',
            'cloud_backup_status',
            'encryption_algorithm',
            'pqc_encrypted',
            'is_signed',
        ]

    is_signed = serializers.SerializerMethodField()

    def get_is_signed(self, obj):
        return bool(obj.pqc_signature)


class DicomFileUploadSerializer(serializers.Serializer):
    file = serializers.FileField()
    patient_id = serializers.CharField(required=False, allow_blank=True)
    patient_name = serializers.CharField(required=False, allow_blank=True)
    study_date = serializers.DateField(required=False, allow_null=True)
    study_description = serializers.CharField(required=False, allow_blank=True)
    modality = serializers.CharField(required=False, allow_blank=True)
    institution_name = serializers.CharField(required=False, allow_blank=True)
    tag = serializers.ChoiceField(
        choices=['ROUTINE', 'URGENT', 'CRITICAL'],
        default='ROUTINE'
    )
    # Optional: attach this upload directly to an existing worklist order
    series_id = serializers.UUIDField(required=False, allow_null=True)


class DicomFileSummarySerializer(serializers.ModelSerializer):
    """Lightweight file listing nested inside a worklist/order response."""

    class Meta:
        model = DicomFile
        fields = ['id', 'original_filename', 'instance_number', 'file_size', 'is_deleted']


class DicomSeriesSerializer(serializers.ModelSerializer):
    """
    The RIS worklist / order serializer. One row here is one order the
    frontend's worklist renders, patient + study + priority + status,
    with its uploaded files nested underneath.
    """

    patient = serializers.SerializerMethodField()
    files = DicomFileSummarySerializer(many=True, read_only=True)
    file_count = serializers.SerializerMethodField()
    assigned_radiologist_name = serializers.CharField(
        source='assigned_radiologist.get_full_name', read_only=True, default=None
    )
    uploaded_by_name = serializers.CharField(source='uploaded_by.get_full_name', read_only=True, default=None)

    class Meta:
        model = DicomSeries
        fields = [
            'id',
            'accession_number',
            'patient',
            'modality',
            'body_part',
            'study_date',
            'series_description',
            'priority',
            'review_status',
            'referring_physician',
            'clinical_indication',
            'assigned_radiologist',
            'assigned_radiologist_name',
            'order_created_at',
            'total_slices',
            'uploaded_slices',
            'file_count',
            'files',
            'cloud_backup_status',
            'uploaded_by',
            'uploaded_by_name',
            'created_at',
        ]

    def get_patient(self, obj):
        return {
            'id': obj.patient_id,
            'name': obj.patient_name,
            'mrn': obj.patient_id,
            'dob': obj.patient_dob,
        }

    def get_file_count(self, obj):
        return obj.files.filter(is_deleted=False).count()


class DicomSeriesCreateSerializer(serializers.Serializer):
    """Payload for creating a new radiology order from the worklist's 'New Order' modal."""

    patient_id = serializers.CharField()
    patient_name = serializers.CharField()
    patient_dob = serializers.DateField(required=False, allow_null=True)
    modality = serializers.CharField()
    body_part = serializers.CharField()
    referring_physician = serializers.CharField()
    priority = serializers.ChoiceField(choices=['routine', 'urgent', 'stat'], default='routine')
    clinical_indication = serializers.CharField(required=False, allow_blank=True)


class AuditLogSerializer(serializers.ModelSerializer):
    user_name = serializers.SerializerMethodField()
    user_role = serializers.SerializerMethodField()
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    dicom_file_name = serializers.SerializerMethodField()
    accession_number = serializers.CharField(source='series.accession_number', read_only=True, default=None)

    class Meta:
        model = AuditLog
        fields = [
            'id',
            'user',
            'user_name',
            'user_role',
            'action',
            'action_display',
            'dicom_file',
            'dicom_file_name',
            'series',
            'accession_number',
            'timestamp',
            'success',
            'details',
            'error_message',
            'ip_address',
            'user_agent',
            'additional_info',
        ]

    def get_user_name(self, obj):
        if obj.user:
            return obj.user.get_full_name() or obj.user.username
        return 'System'

    def get_user_role(self, obj):
        return obj.user.role if obj.user else None

    def get_dicom_file_name(self, obj):
        return obj.dicom_file.original_filename if obj.dicom_file else None


class UserConsentSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserConsent
        fields = '__all__'


class PatientReportSerializer(serializers.ModelSerializer):
    dicom_file_name = serializers.CharField(source='dicom_file.original_filename', read_only=True, default=None)
    patient_name = serializers.SerializerMethodField()
    patient_id = serializers.SerializerMethodField()
    modality = serializers.SerializerMethodField()
    accession_number = serializers.CharField(source='series.accession_number', read_only=True, default=None)
    generated_by_name = serializers.CharField(source='generated_by.get_full_name', read_only=True)

    class Meta:
        model = PatientReport
        fields = [
            'id',
            'dicom_file',
            'dicom_file_name',
            'series',
            'accession_number',
            'patient_name',
            'patient_id',
            'modality',
            'generated_by',
            'generated_by_name',
            'generated_at',
            'clinical_history',
            'technique',
            'findings',
            'impression',
            'recommendations',
            'status',
            'finalized_at',
            'file_size',
            'emailed_to',
            'emailed_at',
            'email_status',
            'is_deleted',
        ]
        read_only_fields = ['id', 'generated_at', 'file_size']

    def _subject(self, obj):
        return obj.series if obj.series else obj.dicom_file

    def get_patient_name(self, obj):
        subj = self._subject(obj)
        return subj.patient_name if subj else None

    def get_patient_id(self, obj):
        subj = self._subject(obj)
        return subj.patient_id if subj else None

    def get_modality(self, obj):
        subj = self._subject(obj)
        return subj.modality if subj else None


class GenerateReportSerializer(serializers.Serializer):
    """Serializer for report generation request. Accepts either a legacy
    single-file id or the new series (order) id, one of the two is required."""

    dicom_file_id = serializers.UUIDField(required=False)
    series_id = serializers.UUIDField(required=False)
    clinical_history = serializers.CharField(required=False, allow_blank=True)
    technique = serializers.CharField(required=False, allow_blank=True)
    findings = serializers.CharField()
    impression = serializers.CharField(required=False, allow_blank=True)
    recommendations = serializers.CharField(required=False, allow_blank=True)
    email_to_patient = serializers.BooleanField(default=False)
    patient_email = serializers.EmailField(required=False, allow_blank=True)

    def validate(self, data):
        if not data.get('dicom_file_id') and not data.get('series_id'):
            raise serializers.ValidationError('Either dicom_file_id or series_id is required.')
        return data


class SignReportSerializer(serializers.Serializer):
    """Finalize and ML-DSA-87 sign a draft report."""
    pass