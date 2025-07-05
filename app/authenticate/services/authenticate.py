import jwt

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from app.accounts.services.user import get_user

User = get_user_model()

class JWTAuthentication(BaseAuthentication):
    def __init__(self) -> None:
        super().__init__()

    def authenticate(self, request):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token expired.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token.")

        jti = payload.get("jti")
        if jti and cache.get(f"blacklisted:jti:{jti}"):
            raise AuthenticationFailed("Token was revoked.")
        
        try:
            user = get_user(payload["user_id"])
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found.")

        return (user, token)
