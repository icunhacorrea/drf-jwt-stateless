from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed, NotFound

from app.accounts.services.user import get_user

User = get_user_model()

def validate_refresh_tokens(payload) -> bool:
    jti = payload.get("jti")
    if cache.get(f"blacklisted:jti:{jti}"):
        raise AuthenticationFailed({"detail": "Refresh token is revoked."})

    try:
        user = get_user(payload["user_id"])
    except User.DoesNotExist:
        raise NotFound({"detail": "User Not Found."})

    exp_timestamp = payload["exp"]
    ttl = exp_timestamp - int(timezone.now().timestamp())
    cache.set(f"blacklisted:jti:{jti}", True, timeout=ttl)

    return user
