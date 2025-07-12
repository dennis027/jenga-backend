from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate
from .serializers import RegisterSerializer, LoginSerializer
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils.timezone import now
from datetime import timedelta

class RegisterView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logged out successfully"}, status=status.HTTP_205_RESET_CONTENT)
        except TokenError:
            return Response({"detail": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        



class CookieLoginView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            if user:
                refresh = RefreshToken.for_user(user)
                response = Response({
                    'message': 'Login successful',
                })

                access_token_expiry = now() + timedelta(minutes=15)
                refresh_token_expiry = now() + timedelta(days=7)

                response.set_cookie(
                    key='access_token',
                    value=str(refresh.access_token),
                    httponly=True,
                    expires=access_token_expiry,
                    samesite='Lax',
                    secure=False  # Change to True in production (HTTPS)
                )
                response.set_cookie(
                    key='refresh_token',
                    value=str(refresh),
                    httponly=True,
                    expires=refresh_token_expiry,
                    samesite='Lax',
                    secure=False
                )
                return response
            return Response({"error": "Invalid credentials"}, status=401)
        return Response(serializer.errors, status=400)