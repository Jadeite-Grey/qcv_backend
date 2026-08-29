import pydicom
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def parse_patient_age(age_str):
    """
    Parse DICOM Age String (AS) format: nnnD, nnnW, nnnM, or nnnY
    (e.g. "045Y", "003M", "002W", "010D"). Returns an integer number
    of years for Y-format ages, otherwise the raw numeric value with
    its unit noted, or None if the field is missing/malformed.

    The old implementation did int(ds.get('PatientAge', '')) directly,
    which crashes on every real DICOM file: the format is never a bare
    integer, and the '' fallback for a missing field can't be cast to
    int either.
    """
    if not age_str:
        return None

    age_str = str(age_str).strip()
    if len(age_str) < 2:
        return None

    unit = age_str[-1].upper()
    number_part = age_str[:-1]

    if not number_part.isdigit():
        return None

    value = int(number_part)

    if unit == 'Y':
        return value
    elif unit == 'M':
        return round(value / 12, 1)
    elif unit == 'W':
        return round(value / 52, 2)
    elif unit == 'D':
        return round(value / 365, 3)
    else:
        # Unrecognized unit — return the raw number rather than guessing
        return value


def parse_dicom_date(date_str):
    """
    Parse DICOM date format (YYYYMMDD) to Python date

    Args:
        date_str: DICOM date string

    Returns:
        date object or None
    """
    if not date_str or len(date_str) < 8:
        return None

    try:
        year = int(date_str[0:4])
        month = int(date_str[4:6])
        day = int(date_str[6:8])
        return datetime(year, month, day).date()
    except (ValueError, TypeError):
        return None


def _extract_metadata_from_dataset(ds):
    """Shared extraction logic used by both file-path and bytes entry points."""
    return {
        'patient_id': str(ds.get('PatientID', '')),
        'patient_name': str(ds.get('PatientName', '')),
        'patient_age': parse_patient_age(ds.get('PatientAge', '')),
        'study_date': parse_dicom_date(str(ds.get('StudyDate', ''))),
        'study_description': str(ds.get('StudyDescription', '')),
        'modality': str(ds.get('Modality', '')),
        'institution_name': str(ds.get('InstitutionName', '')),
        'series_description': str(ds.get('SeriesDescription', '')),
        'body_part_examined': str(ds.get('BodyPartExamined', '')),
    }


def extract_dicom_metadata(file_path):
    try:
        ds = pydicom.dcmread(file_path, force=True)
        metadata = _extract_metadata_from_dataset(ds)
        logger.info(f"Extracted DICOM metadata: Patient ID={metadata['patient_id']}, Modality={metadata['modality']}")
        return metadata
    except pydicom.errors.InvalidDicomError:
        logger.warning(f"File is not a valid DICOM: {file_path}")
        return {}
    except Exception as e:
        logger.error(f"Error extracting DICOM metadata: {str(e)}")
        return {}


def is_valid_dicom(file_path):
    try:
        pydicom.dcmread(file_path, force=True)
        return True
    except Exception:
        return False


def get_dicom_info_from_bytes(file_bytes):
    """Extract DICOM metadata from bytes (for uploaded files)"""
    try:
        from io import BytesIO
        file_obj = BytesIO(file_bytes)
        ds = pydicom.dcmread(file_obj, force=True)
        metadata = _extract_metadata_from_dataset(ds)
        logger.info(f"Extracted DICOM metadata from bytes: Modality={metadata['modality']}")
        return metadata
    except Exception as e:
        logger.error(f"Error extracting DICOM metadata from bytes: {str(e)}")
        return {}


def get_dicom_viewer_metadata(file_bytes):
    """
    Extract the per-slice/series metadata the DICOM viewer needs to
    render correctly: window width/center, pixel spacing, slice
    location. This did not exist in the old dicom_utils.py — the old
    system decrypted and streamed raw DICOM bytes for the browser to
    render, it never returned windowing metadata separately. Used by
    ViewDicomFileView (see the upload/files views chunk) to give the
    frontend viewer real values instead of frontend-side mock defaults.
    """
    try:
        from io import BytesIO
        ds = pydicom.dcmread(BytesIO(file_bytes), force=True)

        def _safe_float(val, default=None):
            try:
                return float(val)
            except (TypeError, ValueError):
                return default

        window_width = ds.get('WindowWidth', None)
        window_center = ds.get('WindowCenter', None)
        # These can be DICOM multi-valued (a list-like), just take the first.
        if hasattr(window_width, '__iter__') and not isinstance(window_width, str):
            window_width = window_width[0] if len(window_width) else None
        if hasattr(window_center, '__iter__') and not isinstance(window_center, str):
            window_center = window_center[0] if len(window_center) else None

        pixel_spacing = ds.get('PixelSpacing', None)
        pixel_spacing_str = None
        if pixel_spacing and len(pixel_spacing) == 2:
            pixel_spacing_str = f"{pixel_spacing[0]} mm / {pixel_spacing[1]} mm"

        return {
            'window_width': _safe_float(window_width),
            'window_center': _safe_float(window_center),
            'pixel_spacing': pixel_spacing_str,
            'slice_thickness': _safe_float(ds.get('SliceThickness', None)),
            'slice_location': _safe_float(ds.get('SliceLocation', None)),
            'rows': int(ds.get('Rows', 0)) or None,
            'columns': int(ds.get('Columns', 0)) or None,
            'instance_number': int(ds.get('InstanceNumber', 0)) or None,
        }
    except Exception as e:
        logger.error(f"Error extracting viewer metadata: {str(e)}")
        return {}


def log_audit_event(request, action, dicom_file=None, success=True, error_message=None, additional_info=None):
    """
    Create audit log entry for HIPAA compliance.
    Kept for parity with the old system; views.py mostly uses the
    create_audit_log() helper defined directly in views.py instead.
    """
    try:
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR', '0.0.0.0')

        from .models import AuditLog
        AuditLog.objects.create(
            action=action,
            dicom_file=dicom_file,
            user=request.user if request.user.is_authenticated else None,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            error_message=error_message,
            additional_info=additional_info or {}
        )
    except Exception as e:
        logger.error(f"Audit logging failed: {e}")


def validate_dicom_file(file):
    """Validate uploaded file is a valid DICOM file"""
    valid_extensions = ['.dcm', '.dicom', '.dcm30', '.dic']
    if not any(file.name.lower().endswith(ext) for ext in valid_extensions):
        return False, "File must have .dcm or .dicom extension"

    if file.size > 2 * 1024 * 1024 * 1024:  # 2GB
        return False, "File too large (max 2GB)"

    if file.size == 0:
        return False, "File is empty"

    return True, None


def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR', '0.0.0.0')