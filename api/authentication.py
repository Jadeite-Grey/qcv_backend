# api/authentication.py
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from api.models import ExpiringToken

class ExpiringTokenAuthentication(TokenAuthentication):
    model = ExpiringToken
    
    def authenticate_credentials(self, key):
        try:
            token = self.model.objects.select_related('user').get(key=key)
        except self.model.DoesNotExist:
            raise AuthenticationFailed('Invalid token')
        
        # THIS MUST BE FIRST - check expiration before anything else
        if token.is_expired():
            token.delete()
            raise AuthenticationFailed('Token expired. Please login again.')
        
        if not token.user.is_active:
            raise AuthenticationFailed('User inactive or deleted')
        
        return (token.user, token)