import jwt
import uuid

from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed

class TokenManager():
    def _generate_payload(self, _id: int, type: str, expires_in: int):
        return {
            "user_id": _id,
            "type": type,
            "exp": timezone.now() + timedelta(minutes=expires_in),
            "jti": str(uuid.uuid4()),
        }
    
    def generate_access_token(self, user):
        payload = self._generate_payload(user.id, "access", 10)
        return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

    def generate_refresh_token(self, user):
        payload = self._generate_payload(user.id, type="refresh", expires_in=60 * 24 * 7)
        return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

    def decode_token(self, token: str, expected_type: str):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token expired.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token.")

        if expected_type and payload.get("type") != expected_type:
            raise AuthenticationFailed("Invalid token type.")

        return payload
