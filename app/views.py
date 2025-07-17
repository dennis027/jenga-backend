from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate,get_user_model
from .serializers import RegisterSerializer, LoginSerializer, UserProfileSerializer,GigSerializer,JobTypeSerializer, PaymentSerializer,GigHistorySerializer
from rest_framework import status, permissions,generics
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils.timezone import now
from datetime import timedelta
from rest_framework.permissions import IsAuthenticated
from .models import Gig,JobType,Payment,GigHistory
from rest_framework.parsers import MultiPartParser, FormParser,JSONParser
from django.db.models import Q 

User = get_user_model()


class CheckEmailExists(APIView):
    def get(self, request):
        email = request.query_params.get('email')
        if not email:
            return Response({"error": "Email parameter is required"}, status=400)
        
        if User.objects.filter(email__iexact=email).exists():
            return Response({"exists": True, "message": "Email already exists"}, status=200)
        return Response({"exists": False, "message": "Email is available"}, status=200)


class CheckUsernameExists(APIView):
    def get(self, request):
        username = request.query_params.get('username')
        if not username:
            return Response({"error": "Username parameter is required"}, status=400)
        
        if User.objects.filter(username__iexact=username).exists():
            return Response({"exists": True, "message": "Username already exists"}, status=200)
        return Response({"exists": False, "message": "Username is available"}, status=200)


class CheckPhoneExists(APIView):
    def get(self, request):
        phone = request.query_params.get('phone')
        if not phone:
            return Response({"error": "Phone parameter is required"}, status=400)
        
        if User.objects.filter(phone__iexact=phone).exists():
            return Response({"exists": True, "message": "Phone number already exists"}, status=200)
        return Response({"exists": False, "message": "Phone number is available"}, status=200)


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
            login_input = serializer.validated_data['username']
            password = serializer.validated_data['password']

            try:
                user = User.objects.get(
                    Q(username__iexact=login_input) |
                    Q(email__iexact=login_input) |
                    Q(phone__iexact=login_input)  # You must ensure your User model has this field
                )
            except User.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)

            user = authenticate(username=user.username, password=password)
            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token)
                })
            else:
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
    



class ProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Profile updated successfully'})
        return Response(serializer.errors, status=400)
    



# 1. Log a new gig
class LogGigView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = GigSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(worker=request.user, logged_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 2. Confirm/Verify a gig by peer or foreman  
class VerifyGigView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, gig_id):
        try:
            gig = Gig.objects.get(id=gig_id)
        except Gig.DoesNotExist:
            return Response({"detail": "Gig not found."}, status=status.HTTP_404_NOT_FOUND)

        if gig.logged_by == request.user:
            return Response({"detail": "You cannot verify your own gig."}, status=status.HTTP_403_FORBIDDEN)

        if gig.is_verified:
            return Response({
                "message": "Gig already verified.",
                "gig_status": "verified",
                "gig": GigSerializer(gig).data
            })

        gig.is_verified = True
        gig.verified_by = request.user
        gig.save()

        return Response({
            "message": "Gig verified successfully.",
            "gig_status": "verified",
            "gig": GigSerializer(gig).data
        }, status=status.HTTP_200_OK)
    

class GigListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        gigs = Gig.objects.all()
        serializer = GigSerializer(gigs, many=True)
        return Response(serializer.data)
    
class LoggedByUserGigListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        gigs = Gig.objects.filter(logged_by=request.user)
        serializer = GigSerializer(gigs, many=True)
        return Response(serializer.data)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)
    


class JobTypeListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = JobType.objects.all()
    serializer_class = JobTypeSerializer


class JobTypeDeleteView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, pk):
        try:
            job_type = JobType.objects.get(pk=pk)
            job_type.delete()
            return Response({"message": "Job type deleted."}, status=status.HTTP_204_NO_CONTENT)
        except JobType.DoesNotExist:
            return Response({"error": "Job type not found."}, status=status.HTTP_404_NOT_FOUND)
        


class PaymentUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]  # allow both

    def post(self, request):
        serializer = PaymentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)  
    


class GigHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = GigHistorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(worker=request.user)  # attach the logged-in user
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    



class UserGigHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        histories = GigHistory.objects.filter(worker=request.user)
        serializer = GigHistorySerializer(histories, many=True)
        return Response(serializer.data)