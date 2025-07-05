from django.core.cache import cache
from django.contrib.auth import get_user_model


User = get_user_model()

def get_user(user_id: int):
    key = f"user_{user_id}"
    
    if entry := cache.get(key):
        return entry

    user = User.objects.filter(id=user_id).first()

    cache.set(key, user, 60 * 24)

    return user
