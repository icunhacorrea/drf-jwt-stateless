from rest_framework import generics
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate

from app.authenticate.serializers import LoginSerializer, RefreshSerializer
from app.authenticate.services.token.manager import TokenManager
from app.authenticate.services.token.refresh import validate_refresh_tokens

class LoginView(generics.CreateAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        manager = TokenManager()
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        user = authenticate(email=email, password=password)
        if not user:
            return Response({"error": "Invalid credentials"}, status=400)

        access_token = manager.generate_access_token(user)
        refresh_token = manager.generate_refresh_token(user)
        return Response({"access_token": access_token, "refresh_token": refresh_token}, 200)

class RefreshView(generics.CreateAPIView):
    serializer_class = RefreshSerializer

    def post(self, request, *args, **kwargs):
        manager = TokenManager()
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)     

        refresh_token = serializer.validated_data["refresh_token"]

        payload = manager.decode_token(refresh_token, "refresh")

        tokens = {}
        if user := validate_refresh_tokens(payload):
            tokens["access_token"]= manager.generate_access_token(user)
            tokens["refresh_token"] = manager.generate_refresh_token(user)

        return Response(tokens, 200)

class ProtectedView(generics.RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response({"message": f"Hello, {request.user.username}!"})
