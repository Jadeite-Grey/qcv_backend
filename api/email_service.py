"""
Email Notification Service
Sends emails via Azure Communication Services
"""
from azure.communication.email import EmailClient
from django.conf import settings
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class EmailService:
    """Handle email notifications via Azure Communication Services"""
    
    def __init__(self):
        if settings.AZURE_COMMUNICATION_CONNECTION_STRING and settings.AZURE_EMAIL_FROM:
            try:
                self.client = EmailClient.from_connection_string(
                    settings.AZURE_COMMUNICATION_CONNECTION_STRING
                )
                self.from_address = settings.AZURE_EMAIL_FROM
                self.enabled = True
                logger.info("✅ Email service initialized with Azure Communication Services")
                logger.info(f"📧 Sending from: {self.from_address}")
            except Exception as e:
                logger.error(f"❌ Failed to initialize email service: {e}")
                self.client = None
                self.enabled = False
        else:
            self.client = None
            self.enabled = False
            logger.warning("⚠️ Email service disabled - missing Azure configuration")
    
    def send_email(self, to_email, subject, body_html):
        """
        Send an email via Azure Communication Services
        
        Args:
            to_email: Recipient email address
            subject: Email subject line
            body_html: HTML body content
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        
        if not self.enabled:
            logger.warning(f"⚠️ Email not sent (service disabled): {subject} to {to_email}")
            return False
        
        try:
            message = {
                "senderAddress": self.from_address,
                "recipients": {
                    "to": [{"address": to_email}]
                },
                "content": {
                    "subject": subject,
                    "html": body_html
                }
            }
            
            logger.info(f"📤 Sending email: '{subject}' to {to_email}")
            
            poller = self.client.begin_send(message)
            result = poller.result()
            
            logger.info(f"✅ Email sent successfully: {subject} to {to_email}")
            logger.info(f"   Message ID: {result.get('id', 'N/A')}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Email failed: {subject} to {to_email}")
            logger.error(f"   Error: {str(e)}")
            return False
    
    def send_test_email(self, to_email):
        """Send a test email to verify configuration"""
        
        subject = "QCV Test Email - Azure Communication Services"
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #1e3a8a;">✅ Email Configuration Successful!</h2>
            <p>This is a test email from your QCV system.</p>
            <p>Azure Communication Services is working correctly.</p>
            <hr>
            <p style="font-size: 12px; color: #64748b;">
                Sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </p>
        </body>
        </html>
        """
        
        return self.send_email(to_email, subject, html_body)
    
    def send_upload_notification(self, user, file_info):
        """Notify user about file upload"""
        
        # Check if user has email and wants notifications
        if not user.email:
            logger.warning(f"⚠️ User {user.username} has no email address")
            return False
        
        # Check user preferences
        prefs = user.notification_preferences or {}
        if not prefs.get('uploadNotifications', False):
            logger.info(f"ℹ️ Upload notifications disabled for {user.username}")
            return False
        
        subject = f"File Uploaded - {file_info['filename']}"
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f8fafc;">
            <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px;">
                <h2 style="color: #1e3a8a;">📁 File Upload Notification</h2>
                <p>Hello <strong>{user.first_name} {user.last_name}</strong>,</p>
                <p>A new DICOM file has been uploaded to your QCV account:</p>
                
                <div style="background: #f1f5f9; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p style="margin: 5px 0;"><strong>Filename:</strong> {file_info['filename']}</p>
                    <p style="margin: 5px 0;"><strong>Patient:</strong> {file_info['patient_name']}</p>
                    <p style="margin: 5px 0;"><strong>Modality:</strong> {file_info['modality']}</p>
                    <p style="margin: 5px 0;"><strong>Study Date:</strong> {file_info['study_date']}</p>
                    <p style="margin: 5px 0;"><strong>File Size:</strong> {file_info['file_size']}</p>
                    <p style="margin: 5px 0;"><strong>Uploaded By:</strong> {file_info['uploaded_by']}</p>
                </div>
                
                <p style="color: #059669;">✅ File encrypted and backed up to cloud successfully</p>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #e2e8f0;">
                
                <p style="font-size: 12px; color: #64748b;">
                    This is an automated notification from QCV - Quantum-Safe DICOM Encryption System.<br>
                    To manage notification preferences, visit Settings → Notifications.
                </p>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(user.email, subject, html_body)
    
    def send_security_alert(self, user, alert_info):
        """Send security alert (always sent, ignores preferences)"""
        
        if not user.email:
            logger.warning(f"⚠️ User {user.username} has no email address")
            return False
        
        subject = f"🚨 Security Alert - {alert_info['title']}"
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f8fafc;">
            <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; border-left: 5px solid #ef4444;">
                <h2 style="color: #ef4444;">🚨 Security Alert</h2>
                <p>Hello <strong>{user.first_name} {user.last_name}</strong>,</p>
                
                <div style="background: #fee2e2; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px solid #ef4444;">
                    <h3 style="margin-top: 0; color: #991b1b;">{alert_info['title']}</h3>
                    <p style="color: #991b1b;">{alert_info['message']}</p>
                </div>
                
                <p><strong>Recommended Action:</strong> {alert_info.get('action', 'Review your account activity.')}</p>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #e2e8f0;">
                
                <p style="font-size: 12px; color: #64748b;">
                    This is an automated security notification from QCV.
                </p>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(user.email, subject, html_body)


# Singleton instance
email_service = EmailService()