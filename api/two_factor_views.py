from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp import user_has_device
import qrcode
import io
import base64
import logging

logger = logging.getLogger(__name__)


class Setup2FAView(APIView):
    """Generate 2FA QR code for user to scan"""
    
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Generate QR code for Google Authenticator"""
        
        user = request.user
        
        # Check if user already has 2FA device
        if user_has_device(user):
            return Response({
                'error': '2FA already enabled for this user',
                'enabled': True
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create TOTP device
        device = TOTPDevice.objects.create(
            user=user,
            name='default',
            confirmed=False
        )
        
        # Generate QR code URL
        qr_url = device.config_url
        
        # Generate QR code image
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        logger.info(f"📱 2FA setup initiated for {user.username}")
        
        return Response({
            'qr_code': f'data:image/png;base64,{img_str}',
            'secret': device.key,
            'user': user.username,
            'message': 'Scan QR code with Google Authenticator app'
        }, status=status.HTTP_200_OK)


class Confirm2FAView(APIView):
    """Confirm 2FA setup by verifying a code"""
    
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """Verify 2FA code to complete setup"""
        
        user = request.user
        code = request.data.get('code')
        
        if not code:
            return Response({
                'error': 'Verification code required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get unconfirmed device
        try:
            device = TOTPDevice.objects.get(user=user, confirmed=False)
        except TOTPDevice.DoesNotExist:
            return Response({
                'error': 'No pending 2FA setup found. Please start setup again.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Verify code
        if device.verify_token(code):
            device.confirmed = True
            device.save()
            
            user.two_factor_enabled = True
            user.two_factor_setup_complete = True
            user.save()
            
            logger.info(f"✅ 2FA confirmed for {user.username}")
            
            return Response({
                'message': '2FA enabled successfully',
                'enabled': True
            }, status=status.HTTP_200_OK)
        else:
            logger.warning(f"⚠️ Invalid 2FA code for {user.username}")
            
            return Response({
                'error': 'Invalid verification code. Please try again.'
            }, status=status.HTTP_400_BAD_REQUEST)


class Disable2FAView(APIView):
    """Disable 2FA for user (requires password confirmation)"""
    
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """Disable 2FA (requires password confirmation)"""
        
        user = request.user
        password = request.data.get('password')
        
        if not password:
            return Response({
                'error': 'Password required to disable 2FA'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not user.check_password(password):
            return Response({
                'error': 'Invalid password'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Delete TOTP devices
        TOTPDevice.objects.filter(user=user).delete()
        
        user.two_factor_enabled = False
        user.two_factor_setup_complete = False
        user.save()
        
        logger.warning(f"⚠️ 2FA disabled for {user.username}")
        
        return Response({
            'message': '2FA disabled successfully',
            'enabled': False
        }, status=status.HTTP_200_OK)


class Check2FAStatusView(APIView):
    """Check if user has 2FA enabled"""
    
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Return 2FA status for current user"""
        
        user = request.user
        
        return Response({
            'enabled': user.two_factor_enabled,
            'setup_complete': user.two_factor_setup_complete,
            'username': user.username
        }, status=status.HTTP_200_OK)