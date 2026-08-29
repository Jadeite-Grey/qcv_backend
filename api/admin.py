from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from .models import User, DicomFile, DicomSeries, AuditLog, UserConsent, PatientReport, Institution


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    list_display = ('username', 'worker_id', 'role', 'institution', 'is_active',
                     'is_activated', 'two_factor_enabled', 'last_login')
    list_filter = ('role', 'is_active', 'is_activated', 'two_factor_enabled', 'institution')
    search_fields = ('username', 'worker_id', 'email', 'first_name', 'last_name')
    ordering = ('-created_at',)

    fieldsets = DjangoUserAdmin.fieldsets + (
        ('QCV Profile', {
            'fields': ('role', 'worker_id', 'institution', 'phone_number',
                       'two_factor_enabled', 'two_factor_setup_complete')
        }),
        ('Account Activation', {
            'fields': ('is_activated', 'password_reset_required', 'password_reset_at')
        }),
        ('PQC Public Keys (secret keys stay encrypted and are never shown here)', {
            'fields': ('pqc_kem_public_key', 'pqc_sig_public_key', 'pqc_enabled'),
        }),
    )
    readonly_fields = ('pqc_kem_public_key', 'pqc_sig_public_key')


@admin.register(DicomSeries)
class DicomSeriesAdmin(admin.ModelAdmin):
    list_display = ('accession_number', 'patient_name', 'patient_id', 'modality',
                     'priority', 'review_status', 'order_created_at')
    list_filter = ('modality', 'priority', 'review_status')
    search_fields = ('accession_number', 'patient_name', 'patient_id')


@admin.register(DicomFile)
class DicomFileAdmin(admin.ModelAdmin):
    list_display = ('original_filename', 'patient_name', 'patient_id', 'modality',
                     'tag', 'cloud_backup_status', 'uploaded_by', 'uploaded_at', 'is_deleted')
    list_filter = ('modality', 'tag', 'cloud_backup_status', 'is_deleted', 'encryption_algorithm')
    search_fields = ('original_filename', 'patient_name', 'patient_id')
    # Key material stays visible-but-readonly here rather than hidden —
    # admins with DB/admin access can already see it via the database
    # directly, so hiding it in this UI wouldn't add real protection,
    # just make legitimate incident investigation harder.
    readonly_fields = ('aes_key', 'iv', 'institutional_encrypted_fek',
                       'institutional_protected_key', 'pqc_signature')


@admin.register(PatientReport)
class PatientReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'series', 'generated_by', 'status', 'generated_at', 'finalized_at')
    list_filter = ('status',)
    readonly_fields = ('pqc_signature_hash',)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'user', 'action', 'success', 'ip_address')
    list_filter = ('action', 'success')
    search_fields = ('user__username', 'details', 'ip_address')
    readonly_fields = [f.name for f in AuditLog._meta.fields]

    # Audit logs are the compliance trail — they shouldn't be editable
    # or deletable from the admin UI, even by superusers.
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(UserConsent)
class UserConsentAdmin(admin.ModelAdmin):
    list_display = ('user', 'data_processing_consent', 'data_storage_consent', 'terms_accepted')


@admin.register(Institution)
class InstitutionAdmin(admin.ModelAdmin):
    list_display = ('name', 'key_version', 'is_active', 'created_at')
    readonly_fields = ('pqc_kem_secret_key_encrypted', 'pqc_kem_secret_key_salt',
                       'pqc_kem_secret_key_nonce')