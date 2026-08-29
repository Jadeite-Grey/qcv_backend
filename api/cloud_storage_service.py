"""
Cloud Storage Service - Dual-mode (Azure + MinIO)
Handles encrypted file backups to public and private cloud
"""
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from minio import Minio
from minio.error import S3Error
from django.conf import settings
import os
import logging
from datetime import datetime
import time

logger = logging.getLogger(__name__)


class CloudStorageService:
    """
    Unified interface for Azure Blob Storage and MinIO
    Supports: azure, minio, or both (redundant)
    """
    
    def __init__(self):
        self.mode = getattr(settings, 'CLOUD_STORAGE_MODE', 'both')
        
        # Initialize Azure client
        if self.mode in ['azure', 'both']:
            self._init_azure()
        
        # Initialize MinIO client
        if self.mode in ['minio', 'both']:
            self._init_minio()
    
    def _init_azure(self):
        """Initialize Azure Blob Storage client"""
        try:
            account_name = settings.AZURE_STORAGE_ACCOUNT_NAME
            account_key = settings.AZURE_STORAGE_ACCOUNT_KEY
            container_name = settings.AZURE_STORAGE_CONTAINER
            
            connection_string = f"DefaultEndpointsProtocol=https;AccountName={account_name};AccountKey={account_key};EndpointSuffix=core.windows.net"
            
            self.azure_blob_service = BlobServiceClient.from_connection_string(connection_string)
            self.azure_container = container_name
            
            # Ensure container exists
            container_client = self.azure_blob_service.get_container_client(container_name)
            if not container_client.exists():
                container_client.create_container()
                logger.info(f"✅ Created Azure container: {container_name}")
            else:
                logger.info(f"✅ Azure container ready: {container_name}")
                
        except Exception as e:
            logger.error(f"❌ Azure initialization failed: {e}")
            raise
    
    def _init_minio(self):
        """Initialize MinIO client"""
        try:
            self.endpoint = settings.MINIO_ENDPOINT
            self.access_key = settings.MINIO_ACCESS_KEY
            self.secret_key = settings.MINIO_SECRET_KEY
            self.use_ssl = settings.MINIO_SECURE
            self.minio_bucket = settings.MINIO_BUCKET

            self.minio_client = Minio(
                self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.use_ssl
            )

            # Ensure bucket exists
            if not self.minio_client.bucket_exists(self.minio_bucket):
                self.minio_client.make_bucket(self.minio_bucket)
                logger.info(f"✅ Created MinIO bucket: {self.minio_bucket}")
            else:
                logger.info(f"✅ MinIO bucket ready: {self.minio_bucket}")

            logger.info("✅ MinIO client initialized successfully")

        except Exception as e:
            logger.warning(f"⚠️ MinIO unavailable: {e}")
            self.minio_client = None
    
    def upload_file(self, local_path, blob_name, metadata=None):
        """
        Upload file to cloud storage
        
        Args:
            local_path: Path to local file
            blob_name: Name for the blob/object in cloud
            metadata: Optional metadata dict
            
        Returns:
            dict with upload results
        """
        results = {
            'success': False,
            'azure': None,
            'minio': None,
            'timestamp': datetime.now().isoformat()
        }
        
        # Upload to Azure
        if self.mode in ['azure', 'both']:
            try:
                azure_result = self._upload_to_azure(local_path, blob_name, metadata)
                results['azure'] = azure_result
                logger.info(f"✅ Uploaded to Azure: {blob_name}")
            except Exception as e:
                logger.error(f"❌ Azure upload failed: {e}")
                results['azure'] = {'error': str(e)}
        
        # Upload to MinIO
        if self.mode in ['minio', 'both']:
            try:
                minio_result = self._upload_to_minio(local_path, blob_name, metadata)
                results['minio'] = minio_result
                logger.info(f"✅ Uploaded to MinIO: {blob_name}")
            except Exception as e:
                logger.error(f"❌ MinIO upload failed: {e}")
                results['minio'] = {'error': str(e)}
        
        # Mark as success if at least one upload worked
        results['success'] = (
            (results['azure'] and 'error' not in results['azure']) or
            (results['minio'] and 'error' not in results['minio'])
        )
        
        return results
    
    def _upload_to_azure(self, local_path, blob_name, metadata=None):
        """Upload file to Azure Blob Storage with retry and chunking"""
        from azure.core.exceptions import AzureError
        
        file_size = os.path.getsize(local_path)
        max_retries = 3
        retry_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                logger.info(f"📤 Azure upload attempt {attempt + 1}/{max_retries} ({file_size / (1024*1024):.2f} MB)")
                
                blob_client = self.azure_blob_service.get_blob_client(
                    container=self.azure_container,
                    blob=blob_name
                )
                
                # Use chunked upload for files > 4MB
                if file_size > 4 * 1024 * 1024:  # 4MB threshold
                    logger.info(f"📦 Using chunked upload (4MB chunks)")
                    
                    with open(local_path, 'rb') as data:
                        blob_client.upload_blob(
                            data,
                            overwrite=True,
                            metadata=metadata or {},
                            max_concurrency=1,  # Upload one chunk at a time for stability
                            timeout=300,  # 5 minutes per chunk
                            connection_timeout=120,  # 2 minutes connection timeout
                        )
                else:
                    # Small files: simple upload
                    logger.info(f"📄 Using simple upload")
                    
                    with open(local_path, 'rb') as data:
                        blob_client.upload_blob(
                            data,
                            overwrite=True,
                            metadata=metadata or {},
                            timeout=300,
                            connection_timeout=120
                        )
                
                # Success - get properties and return
                props = blob_client.get_blob_properties()
                
                logger.info(f"✅ Azure upload successful on attempt {attempt + 1}")
                
                return {
                    'url': blob_client.url,
                    'size': props.size,
                    'etag': props.etag,
                    'last_modified': props.last_modified.isoformat(),
                    'provider': 'Azure Blob Storage',
                    'attempts': attempt + 1
                }
            
            except (AzureError, TimeoutError, OSError) as e:
                logger.warning(f"⚠️ Azure upload attempt {attempt + 1} failed: {type(e).__name__}: {e}")
                
                if attempt < max_retries - 1:
                    logger.info(f"🔄 Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff (5s, 10s, 20s)
                else:
                    logger.error(f"❌ All {max_retries} Azure upload attempts failed")
                    raise
            
            except Exception as e:
                logger.error(f"❌ Unexpected error during Azure upload: {type(e).__name__}: {e}")
                raise
    
    def _upload_to_minio(self, local_path, blob_name, metadata=None):
        """Upload file to MinIO"""
        file_size = os.path.getsize(local_path)
        
        logger.info(f"📤 MinIO upload starting ({file_size / (1024*1024):.2f} MB)")
        
        self.minio_client.fput_object(
            self.minio_bucket,
            blob_name,
            local_path,
            metadata=metadata or {}
        )
        
        # Get object info
        stat = self.minio_client.stat_object(self.minio_bucket, blob_name)
        
        return {
            'bucket': self.minio_bucket,
            'object': blob_name,
            'size': stat.size,
            'etag': stat.etag,
            'last_modified': stat.last_modified.isoformat(),
            'provider': 'MinIO Private Cloud'
        }
    
    def download_file(self, blob_name, destination_path):
        """
        Download file from cloud storage
        Tries Azure first, falls back to MinIO
        
        Args:
            blob_name: Name of blob/object
            destination_path: Local path to save file
            
        Returns:
            dict with download result
        """
        # Try Azure first
        if self.mode in ['azure', 'both']:
            try:
                result = self._download_from_azure(blob_name, destination_path)
                logger.info(f"✅ Downloaded from Azure: {blob_name}")
                return result
            except Exception as e:
                logger.warning(f"⚠️ Azure download failed: {e}")
                if self.mode == 'azure':
                    raise
        
        # Try MinIO
        if self.mode in ['minio', 'both']:
            try:
                result = self._download_from_minio(blob_name, destination_path)
                logger.info(f"✅ Downloaded from MinIO: {blob_name}")
                return result
            except Exception as e:
                logger.error(f"❌ MinIO download failed: {e}")
                raise
        
        raise Exception("No cloud storage providers available")
    
    def _download_from_azure(self, blob_name, destination_path):
        """Download file from Azure Blob Storage"""
        blob_client = self.azure_blob_service.get_blob_client(
            container=self.azure_container,
            blob=blob_name
        )
        
        with open(destination_path, 'wb') as download_file:
            download_file.write(blob_client.download_blob().readall())
        
        return {
            'path': destination_path,
            'size': os.path.getsize(destination_path),
            'provider': 'Azure Blob Storage'
        }
    
    def _download_from_minio(self, blob_name, destination_path):
        """Download file from MinIO"""
        self.minio_client.fget_object(
            self.minio_bucket,
            blob_name,
            destination_path
        )
        
        return {
            'path': destination_path,
            'size': os.path.getsize(destination_path),
            'provider': 'MinIO Private Cloud'
        }
    
    def list_backups(self):
        """List all backups in cloud storage"""
        backups = {
            'azure': [],
            'minio': []
        }
        
        # List Azure blobs
        if self.mode in ['azure', 'both']:
            try:
                container_client = self.azure_blob_service.get_container_client(self.azure_container)
                for blob in container_client.list_blobs():
                    backups['azure'].append({
                        'name': blob.name,
                        'size': blob.size,
                        'last_modified': blob.last_modified.isoformat(),
                        'provider': 'Azure'
                    })
            except Exception as e:
                logger.error(f"❌ Failed to list Azure blobs: {e}")
        
        # List MinIO objects
        if self.mode in ['minio', 'both']:
            try:
                objects = self.minio_client.list_objects(self.minio_bucket)
                for obj in objects:
                    last_modified = obj.last_modified.isoformat() if obj.last_modified else 'Unknown'
                    backups['minio'].append({
                        'name': obj.object_name,
                        'size': obj.size,
                        'last_modified': last_modified,
                        'provider': 'MinIO'
                    })
            except Exception as e:
                logger.error(f"❌ Failed to list MinIO objects: {e}")
        
        return backups
    
    def delete_backup(self, blob_name):
        """Delete backup from cloud storage"""
        results = {}
        
        # Delete from Azure
        if self.mode in ['azure', 'both']:
            try:
                blob_client = self.azure_blob_service.get_blob_client(
                    container=self.azure_container,
                    blob=blob_name
                )
                blob_client.delete_blob()
                results['azure'] = 'deleted'
                logger.info(f"✅ Deleted from Azure: {blob_name}")
            except Exception as e:
                results['azure'] = f'error: {e}'
        
        # Delete from MinIO
        if self.mode in ['minio', 'both']:
            try:
                self.minio_client.remove_object(self.minio_bucket, blob_name)
                results['minio'] = 'deleted'
                logger.info(f"✅ Deleted from MinIO: {blob_name}")
            except Exception as e:
                results['minio'] = f'error: {e}'
        
        return results

    def get_cloud_path(self, dicom_file):
        """Generate organized cloud path with encrypted filename"""
        # Sanitize patient name for filesystem
        patient_name = dicom_file.patient_name.replace('^', '_').replace(' ', '_')
        patient_name = ''.join(c for c in patient_name if c.isalnum() or c == '_')
        
        # Get study date
        study_date = dicom_file.study_date.strftime('%Y-%m-%d') if dicom_file.study_date else 'UNKNOWN_DATE'
        
        # Path: patients/NAME_ID/MODALITY_DATE/uuid.enc
        cloud_path = f"patients/{patient_name}_{dicom_file.patient_id}/{dicom_file.modality}_{study_date}/{dicom_file.id}.enc"
        
        return cloud_path


# Singleton instance
cloud_storage_service = CloudStorageService()