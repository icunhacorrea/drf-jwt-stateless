from rest_framework import serializers

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)


class RefreshSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)
