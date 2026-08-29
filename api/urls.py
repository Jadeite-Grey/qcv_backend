from django.urls import path

from api.two_factor_views import (
    Setup2FAView,
    Confirm2FAView,
    Disable2FAView,
    Check2FAStatusView,
)

from .views import (
    LoginView,
    SessionStatusView,
    LogoutView,
    Verify2FAView,

    ListOrdersView,
    CreateOrderView,
    UpdateOrderStatusView,

    UploadDicomView,
    ListDicomFilesView,
    GetFileDetailsView,
    DownloadDicomView,
    ViewDicomFileView,
    DeleteDicomFileView,

    GenerateReportView,
    SignReportView,
    ListReportsView,
    DownloadReportView,
    EmailReportView,

    DashboardStatsView,
    SystemHealthView,

    ListUsersView,
    CreateUserView,
    UpdateUserView,
    DeleteUserView,
    GetUserView,

    ActivateAccountView,
    SetPasswordView,
    UpdateProfileView,
    ChangePasswordView,
    UpdatePreferencesView,
    RegenerateUserKeysView,
    ForcePasswordChangeView,

    CloudSyncView,
    SystemAlertsView,
    CloudSyncMonitorView,
    ErrorRecoveryView,
    CloudStorageStatsView,
    NotificationsView,
    CheckDuplicateView,
    UpdateMetadataView,
    GroupedFilesView,

    AuditLogView,
    BulkResignFilesView,
    SecurityDashboardView,
    DeleteInvalidFilesView,
    RecoverableFilesView,
    RecoverFromCloudView,
    BulkRecoverFromCloudView,
)

urlpatterns = [
    # Auth
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/verify-2fa/', Verify2FAView.as_view(), name='verify-2fa'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/session-status/', SessionStatusView.as_view(), name='session-status'),
    path('auth/force-password-change/', ForcePasswordChangeView.as_view(), name='force_password_change'),
    path('auth/2fa/status/', Check2FAStatusView.as_view(), name='2fa-status'),
    path('auth/2fa/setup/', Setup2FAView.as_view(), name='2fa-setup'),
    path('auth/2fa/confirm/', Confirm2FAView.as_view(), name='2fa-confirm'),
    path('auth/2fa/disable/', Disable2FAView.as_view(), name='2fa-disable'),

    # RIS Worklist
    path('worklist/', ListOrdersView.as_view(), name='list-orders'),
    path('worklist/create/', CreateOrderView.as_view(), name='create-order'),
    path('worklist/<uuid:order_id>/status/', UpdateOrderStatusView.as_view(), name='update-order-status'),

    # Upload / Files / Viewer
    path('upload/', UploadDicomView.as_view(), name='upload-dicom'),
    path('files/', ListDicomFilesView.as_view(), name='list-files'),
    path('files/grouped/', GroupedFilesView.as_view(), name='grouped-files'),
    path('files/check-duplicate/', CheckDuplicateView.as_view(), name='check-duplicate'),
    path('files/<uuid:file_id>/details/', GetFileDetailsView.as_view(), name='file-details'),
    path('files/<uuid:file_id>/download/', DownloadDicomView.as_view(), name='download-file'),
    path('files/<uuid:file_id>/view/', ViewDicomFileView.as_view(), name='view-dicom-file'),
    path('files/<uuid:file_id>/metadata/', UpdateMetadataView.as_view(), name='update-metadata'),
    path('files/<uuid:file_id>/', DeleteDicomFileView.as_view(), name='delete_dicom_file'),

    # Reports
    path('reports/generate/', GenerateReportView.as_view(), name='generate-report'),
    path('reports/', ListReportsView.as_view(), name='list-reports'),
    path('reports/<uuid:report_id>/sign/', SignReportView.as_view(), name='sign-report'),
    path('reports/<uuid:report_id>/download/', DownloadReportView.as_view(), name='download-report'),
    path('reports/<uuid:report_id>/email/', EmailReportView.as_view(), name='email-report'),

    # Dashboard / System health
    path('dashboard/stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    path('system/health/', SystemHealthView.as_view(), name='system-health'),

    # Users / Admin
    path('users/', ListUsersView.as_view(), name='list-users'),
    path('users/create/', CreateUserView.as_view(), name='create-user'),
    path('users/<uuid:user_id>/', GetUserView.as_view(), name='get-user'),
    path('users/<uuid:user_id>/update/', UpdateUserView.as_view(), name='update-user'),
    path('users/<uuid:user_id>/delete/', DeleteUserView.as_view(), name='delete-user'),
    path('users/<uuid:user_id>/regenerate-keys/', RegenerateUserKeysView.as_view(), name='regenerate_user_keys'),

    # Activation / Profile
    path('activate/<str:uidb64>/<str:token>/', ActivateAccountView.as_view(), name='activate-account'),
    path('activate/<str:uidb64>/<str:token>/set-password/', SetPasswordView.as_view(), name='set-password'),
    path('profile/update/', UpdateProfileView.as_view(), name='update-profile'),
    path('profile/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('profile/preferences/', UpdatePreferencesView.as_view(), name='update-preferences'),

    # Cloud sync / alerts / recovery
    path('cloud/sync/', CloudSyncView.as_view(), name='cloud-sync'),
    path('cloud/recoverable-files/', RecoverableFilesView.as_view(), name='recoverable-files'),
    path('files/recover-from-cloud/', RecoverFromCloudView.as_view(), name='recover-from-cloud'),
    path('files/bulk-recover-from-cloud/', BulkRecoverFromCloudView.as_view(), name='bulk-recover-from-cloud'),
    path('it/alerts/', SystemAlertsView.as_view(), name='system-alerts'),
    path('it/sync-monitor/', CloudSyncMonitorView.as_view(), name='sync-monitor'),
    path('it/error-recovery/', ErrorRecoveryView.as_view(), name='error-recovery'),
    path('it/cloud-storage/', CloudStorageStatsView.as_view(), name='cloud-storage-stats'),
    path('notifications/', NotificationsView.as_view(), name='notifications'),

    # Audit / Security
    path('audit-logs/', AuditLogView.as_view(), name='audit-logs'),
    path('files/bulk-resign/', BulkResignFilesView.as_view(), name='bulk_reassign_key_file'),
    path('files/delete-invalid/', DeleteInvalidFilesView.as_view(), name='delete-invalid-files'),
    path('security/', SecurityDashboardView.as_view(), name='security-dashboard'),
]