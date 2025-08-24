from django.shortcuts import redirect,render
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate,get_user_model
from .serializers import CreditScoreHistorySerializer, GigCompletionRateSerializer, GigCountSerializer, GigRevenueSerializer, GigTrendsSerializer, GigsAvailableSerializer, RegisterSerializer, LoginSerializer, TopGigsSerializer, UserProfileSerializer,GigSerializer,JobTypeSerializer, PaymentSerializer,GigHistorySerializer,OrganizationSerializer,UserSerializer,UserDetailWithGigsSerializer,MpesaNewTransactionSerializer, VerificationRequestSerializer,  WeeklyWorkerReportSerializer,WeeklyGigReportSerializer,JobTypeDistributionSerializer,OrgPerformanceSerializer,VerificationImpactSerializer
from rest_framework import status, permissions,generics
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils.timezone import now
from datetime import timedelta
from rest_framework.permissions import IsAuthenticated
from .models import CreditScoreHistory, Gig, GigsAvailable,JobType,GigHistory, Organization,MpesaNewTransaction,UserPaymentSession,PhoneOTP, VerificationRequest
from rest_framework.parsers import MultiPartParser, FormParser,JSONParser
from django.db.models import Q 
import logging
import base64
from rest_framework.parsers import JSONParser
from datetime import datetime
from django.utils import timezone
from rest_framework.permissions import AllowAny
import pytesseract
from PIL import Image
from django.core.files.storage import default_storage
from django.http import JsonResponse
import re
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.conf import settings
from django.db.models import Q
import random  
from django.core.mail import send_mail
from .models import PasswordResetCode
from django.middleware.csrf import get_token
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode
from django.urls import reverse
from django.template.loader import render_to_string
from .afritesting import send_sms
import africastalking
from django.views import View
import json
from datetime import datetime
from django.db.models import Count, Q, Avg, Sum
from django.db.models.functions import  ExtractWeek, ExtractYear, TruncMonth, TruncYear, TruncWeek




# mpesa credentials
BUSINESS_SHORTCODE = settings.MPESA_SHORTCODE
PASSKEY = settings.MPESA_PASSKEY
CONSUMER_KEY = settings.MPESA_CONSUMER_KEY
CONSUMER_SECRET = settings.MPESA_CONSUMER_SECRET
CALLBACK_URL = settings.MPESA_CALLBACK_URL


logger = logging.getLogger(__name__)


User = get_user_model()


class CheckEmailExists(APIView):
    permission_classes = [AllowAny] 
    def get(self, request):
        email = request.query_params.get('email')
        if not email:
            return Response({"error": "Email parameter is required"}, status=400)
        
        if User.objects.filter(email__iexact=email).exists():
            return Response({"exists": True, "message": "Email already exists"}, status=200)
        return Response({"exists": False, "message": "Email is available"}, status=400)


class CheckUsernameExists(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        username = request.query_params.get('username')
        if not username:
            return Response({"error": "Username parameter is required"}, status=400)
        
        if User.objects.filter(username__iexact=username).exists():
            return Response({"exists": True, "message": "Username already exists"}, status=200)
        return Response({"exists": False, "message": "Username is available"}, status=400)


class UserListAPIView(APIView):
    permission_classes = [IsAuthenticated]  # Remove if public access is okay

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


class CheckPhoneExists(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        phone = request.query_params.get('phone')
        if not phone:
            return Response({"error": "Phone parameter is required"}, status=400)
        
        if User.objects.filter(phone__iexact=phone).exists():
            return Response({"exists": True, "message": "Phone number already exists"}, status=200)
        return Response({"exists": False, "message": "Phone number is available"}, status=400)

class RegisterView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        print(request.data)  # Debugging line to check incoming data
        if serializer.is_valid():
            user = serializer.save()
            user.is_verified = False
            user.save()

            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            activation_link = request.build_absolute_uri(
                reverse('activate', kwargs={'uidb64': uidb64, 'token': token})
            )

            subject = "Activate Your Account"
            html_content = render_to_string('activation/activation_email.html', {
                'username': user.username,
                'activation_link': activation_link
            })

            try:
                send_mail(subject, '', settings.DEFAULT_FROM_EMAIL, [user.email], html_message=html_content)
            except Exception as e:
                return Response({"error": f"Failed to send activation email: {str(e)}"},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"message": "Registration successful. Please check your email to activate your account."},
                            status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ActivateAccountAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid link"}, status=400)

        if default_token_generator.check_token(user, token):
            user.is_verified = True
            user.save()
            # return Response({"message": "Account activated successfully"})
            request.session['activation_done'] = True 
            return redirect('/activation-success/')
        else:
            # return Response({"error": "Invalid or expired token"}, status=400)
            request.session['activation_done'] = True 
            return redirect('/activation-failed/')
        
        
        
class ResendVerificationEmailView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        # Check if already verified
        if user.is_verified:
            return Response({"message": "Your account is already verified."}, status=status.HTTP_400_BAD_REQUEST)

        # Generate new token and link
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        activation_link = request.build_absolute_uri(
            reverse('activate', kwargs={'uidb64': uidb64, 'token': token})
        )

        subject = "Activate Your Account"
        html_content = render_to_string('activation/activation_email.html', {
            'username': user.username,
            'activation_link': activation_link
        })

        try:
            send_mail(subject, '', settings.DEFAULT_FROM_EMAIL, [user.email], html_message=html_content)
        except Exception as e:
            return Response({"error": f"Failed to send activation email: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Verification email sent. Please check your inbox."},
                        status=status.HTTP_200_OK)




def activation_success_view(request):
    if request.session.pop('activation_done', None):  # remove flag after use
        return render(request, 'activation/activation_success.html')
    return redirect('/')  # or 404 page


def activation_failed_view(request):
    if request.session.pop('activation_done', None):
        return render(request, 'activation/activation_failed.html')
    return redirect('/')





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
        

# password reset code generation
class RequestPasswordResetView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Don't reveal if user exists (security)
            return Response({"message": "If this email exists, a reset code has been sent."})

        # Generate a 6-digit code
        code = str(random.randint(100000, 999999))
        PasswordResetCode.objects.create(user=user, code=code)

        send_mail(
            subject="Your Password Reset Code",
            message=f"Your password reset code is: {code}\nThis code will expire in 30 minutes.",
            from_email=None,
            recipient_list=[email],
            fail_silently=False,
        )

        return Response({"message": "If this email exists, a reset code has been sent."})
    
@ensure_csrf_cookie
@require_http_methods(["GET"])
def csrf_token_view(request):
    return JsonResponse({'csrf_token': get_token(request)})
    
@method_decorator(csrf_exempt, name='dispatch')
class VerifyResetCodeView(APIView):
    authentication_classes = []  # Disable DRF authentication
    permission_classes = []      # Disable DRF permissions
    
    def post(self, request):
        email = request.data.get('email')
        code = request.data.get('code')

        if not email or not code:
            return Response({"error": "Email and code are required"}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "Invalid email or code"}, status=400)

        try:
            reset_code = PasswordResetCode.objects.filter(
                user=user, code=code
            ).latest('created_at')
        except PasswordResetCode.DoesNotExist:
            return Response({"error": "Invalid code"}, status=400)

        if reset_code.is_expired():
            return Response({"error": "Code expired"}, status=400)

        return Response({"message": "Code is valid"}, status=200)

        
class ConfirmResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        code = request.data.get('code')
        new_password = request.data.get('new_password')
        reset_password = request.data.get('reset_password')  # confirm password

        # Check all required fields
        if not all([email, code, new_password, reset_password]):
            return Response({"error": "Email, code, new_password, and reset_password are required"}, status=400)

        # Check if passwords match
        if new_password != reset_password:
            return Response({"error": "Passwords do not match"}, status=400)

        # Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "Invalid email or code"}, status=400)

        # Check if code exists
        try:
            reset_code = PasswordResetCode.objects.filter(user=user, code=code).latest('created_at')
        except PasswordResetCode.DoesNotExist:
            return Response({"error": "Invalid code"}, status=400)

        # Check if code expired
        if reset_code.is_expired():
            return Response({"error": "Code expired"}, status=400)

        # Reset password
        user.set_password(new_password)
        user.save()

        # Remove the code after successful reset
        reset_code.delete()

        return Response({"message": "Password reset successful"})



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
    



class LogGigView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = GigSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(
                worker=request.user,        # ✅ Assign worker from authenticated user
                logged_by=request.user      # ✅ Assign logged_by as well
            )
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

        # Prevent self-verification
        if gig.logged_by == request.user:
            return Response({"detail": "You cannot verify your own gig."}, status=status.HTTP_403_FORBIDDEN)

        # Prevent double verification
        if gig.is_verified:
            return Response({
                "message": "Gig already verified.",
                "gig_status": "verified",
                "gig": GigSerializer(gig).data
            })

        # Mark gig as verified
        gig.is_verified = True
        gig.verified_by = request.user
        gig.save()

        # ✅ Update worker's credit score (using User model)
        worker = gig.logged_by
        if hasattr(worker, "credit_score"):  # Ensure the field exists
            worker.credit_score = worker.credit_score + 5  # Increase score
            worker.save()

            # log history
            CreditScoreHistory.objects.create(
            user=worker,
            change=+5,
            new_score=worker.credit_score,
            action="verify_gig"
    )

        return Response({
            "message": "Gig verified successfully.",
            "gig_status": "verified",
            "gig": GigSerializer(gig).data,
            "worker_credit_score": worker.credit_score
        }, status=status.HTTP_200_OK)


# verify gigs
@method_decorator(csrf_exempt, name='dispatch')
class CompleteGigAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, gig_id):
        try:
            gig = Gig.objects.get(id=gig_id)
        except Gig.DoesNotExist:
            return Response({"error": "Gig not found"}, status=status.HTTP_404_NOT_FOUND)

        if not gig.is_verified:
            return Response({"error": "Gig must be verified before marking as complete"}, status=status.HTTP_400_BAD_REQUEST)

        # Create history record
        gig_history = GigHistory.objects.create(
            worker=gig.worker,
            job_type=gig.job_type,
            start_date=gig.start_date,
            duration_value=gig.duration_value,
            duration_unit=gig.duration_unit,
            client_name=gig.client_name,
            client_phone=gig.client_phone,
            county=gig.county,
            constituency=gig.constituency,
            ward=gig.ward,
            is_verified=gig.is_verified,
            organization=gig.organization
        )

        # Update credit score (+10 on completion) directly on User model
        worker = gig.worker  # this is already a User
        worker.credit_score = (worker.credit_score or 0) + 5
        worker.save()
        CreditScoreHistory.objects.create(
            user=worker,
            change=+5,
            new_score=worker.credit_score,
            action="verify_gig"
        )

        # Delete gig after moving
        gig.delete()

        return Response(
            {
                "message": "Gig moved to history successfully",
                "history_id": gig_history.id,
                "new_score": worker.credit_score,
            },
            status=status.HTTP_200_OK
        )


# GIG HIstory

class CreditScoreHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        history = CreditScoreHistory.objects.filter(user=request.user).order_by("timestamp")
        return Response(CreditScoreHistorySerializer(history, many=True).data)





#SEARCH GIGS

class GigSearchView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        county = request.query_params.get('county')
        constituency = request.query_params.get('constituency')
        ward = request.query_params.get('ward')
        job_type = request.query_params.get('job_type')  # ID of JobType
        client_name = request.query_params.get('client_name')

        gigs = Gig.objects.all()

        if county:
            gigs = gigs.filter(county__icontains=county)
        if constituency:
            gigs = gigs.filter(constituency__icontains=constituency)
        if ward:
            gigs = gigs.filter(ward__icontains=ward)
        if job_type:
            gigs = gigs.filter(job_type_id=job_type)
        if client_name:
            gigs = gigs.filter(client_name__icontains=client_name)

        serializer = GigSerializer(gigs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

    

class GigListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        gigs = Gig.objects.all()
        
        serializer = GigSerializer(gigs, many=True)
        return Response(serializer.data)
    


class GigsAvailableListCreateView(generics.ListCreateAPIView):
    serializer_class = GigsAvailableSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Show only gigs from the organizations owned by the logged-in user
        return GigsAvailable.objects.all().order_by('-created_at')

    def perform_create(self, serializer):
        org_id = self.request.data.get("organization")
        try:
            organization = Organization.objects.get(id=org_id, owner=self.request.user)
        except Organization.DoesNotExist:
            raise PermissionError("You do not own this organization or it does not exist.")
        
        serializer.save(organization=organization)


class UserOrganizationGigListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get all organizations owned by the logged-in user
        user_orgs = Organization.objects.filter(owner=request.user)

        # Filter gigs that belong to those organizations
        gigs = Gig.objects.filter(organization__in=user_orgs)

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

    def get(self, request):
        # get only history belonging to the logged-in user
        histories = GigHistory.objects.filter(worker=request.user).order_by('-created_at')
        serializer = GigHistorySerializer(histories, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    


# single organization gigs view
class OrganizationGigsAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, org_id):
        try:
            organization = Organization.objects.get(id=org_id)
        except Organization.DoesNotExist:
            return Response({'error': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        gigs = Gig.objects.filter(organization=organization)
        serializer = GigSerializer(gigs, many=True)
        return Response(serializer.data)



class UserGigHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        histories = GigHistory.objects.filter(worker=request.user)
        serializer = GigHistorySerializer(histories, many=True)
        return Response(serializer.data)
    


# organization model

class OrganizationListCreateView(generics.ListCreateAPIView):
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Organization.objects.all().order_by("id")

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

#user organization list view
class UserOrganizationListCreateView(generics.ListCreateAPIView):
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Only return organizations owned by the logged-in user
        return Organization.objects.filter(owner=self.request.user).order_by("id")

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

class OrganizationDetailUpdateView(generics.RetrieveUpdateAPIView):
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'pk'

    def get_queryset(self):
        return Organization.objects.filter(owner=self.request.user)

class OrganizationSoftDeleteView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            organization = Organization.objects.get(pk=pk, owner=request.user)
            organization.is_active = not organization.is_active
            organization.save()
            return Response({
                "status": "success",
                "message": f"Organization is_active set to {organization.is_active}"
            })
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)
        


class WorkerSearchAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]  # only logged-in users can search

    def get(self, request, *args, **kwargs):
        query = request.query_params.get('q', None)

        if not query:
            return Response(
                {"error": "Please provide a search query (?q=)"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(
                Q(username__iexact=query) |
                Q(email__iexact=query) |
                Q(phone__iexact=query) |
                Q(full_name__icontains=query) |   # NEW: search by full_name
                Q(national_id__iexact=query)      # NEW: search by national_id
            )
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        # Serialize worker details along with gigs
        data = UserDetailWithGigsSerializer(user).data
        return Response(data, status=status.HTTP_200_OK)
    

@csrf_exempt
def extract_transaction_code(request):
    if request.method == 'POST' and request.FILES.get('image'):
        uploaded_image = request.FILES['image']
        file_path = default_storage.save('temp/' + uploaded_image.name, uploaded_image)

        image = Image.open(default_storage.path(file_path))
        text = pytesseract.image_to_string(image)
        
        # Clean up temp file
        default_storage.delete(file_path)
        
        # Clean and normalize text
        clean_text = text.strip().replace('\n', ' ').replace('\r', ' ')
        clean_text = ' '.join(clean_text.split())  # Remove extra whitespace
        text_lower = clean_text.lower()
        
        # Check if it's a valid M-Pesa message
        mpesa_indicators = ['confirmed', 'ksh', 'sent to', 'received from', 'mpesa']
        found_indicators = sum(1 for indicator in mpesa_indicators if indicator in text_lower)
        is_valid_mpesa = found_indicators >= 3
        
        # Check for message completeness
        completeness_indicators = ['confirmed', 'ksh', 'transaction cost', 'account balance']
        completeness_score = sum(1 for indicator in completeness_indicators if indicator in text_lower)
        is_complete = completeness_score >= 3 or ('sent to' in text_lower or 'received from' in text_lower)
        
        # Extract transaction code - multiple patterns
        transaction_code = None
        
        # Pattern 1: Code before "Confirmed"
        match = re.search(r'\b([A-Z0-9]{8,12})\b(?=\s+[Cc]onfirmed)', clean_text)
        if match:
            transaction_code = match.group(1)
        else:
            # Pattern 2: Code after "Confirmed"
            match = re.search(r'[Cc]onfirmed\.?\s+([A-Z0-9]{8,12})', clean_text)
            if match:
                transaction_code = match.group(1)
            else:
                # Pattern 3: General M-Pesa code format
                codes = re.findall(r'\b([A-Z]{2}[0-9]{8}|[A-Z0-9]{10})\b', clean_text)
                false_positives = ['MPESA', 'SAFARICOM', 'CONFIRMED']
                valid_codes = [code for code in codes if code not in false_positives and len(code) >= 8]
                if valid_codes:
                    transaction_code = valid_codes[0]
        
        # Extract amount - multiple patterns
        amount = None
        
        # Pattern 1: Amount before "sent to" or "received from"
        match = re.search(r'[Kk][Ss][Hh]\.?\s*([0-9,]+\.?[0-9]*)\s+(?:sent\s+to|received\s+from)', clean_text, re.IGNORECASE)
        if match:
            amount_str = match.group(1).replace(',', '').strip()
            try:
                amount = float(amount_str)
            except ValueError:
                pass
        
        if not amount:
            # Pattern 2: Amount after "Confirmed"
            match = re.search(r'[Cc]onfirmed\.?\s+[Kk][Ss][Hh]\.?\s*([0-9,]+\.?[0-9]*)', clean_text)
            if match:
                amount_str = match.group(1).replace(',', '').strip()
                try:
                    amount = float(amount_str)
                except ValueError:
                    pass
        
        if not amount:
            # Pattern 3: Any KSH amount (take the largest one)
            amounts = re.findall(r'[Kk][Ss][Hh]\.?\s*([0-9,]+\.?[0-9]*)', clean_text)
            if amounts:
                valid_amounts = []
                for amt in amounts:
                    try:
                        clean_amt = float(amt.replace(',', '').strip())
                        if clean_amt > 0:
                            valid_amounts.append(clean_amt)
                    except ValueError:
                        continue
                if valid_amounts:
                    amount = max(valid_amounts)  # Take the largest amount (likely the transaction amount)

        return JsonResponse({
            'text': text,
            'transaction_code': transaction_code,
            'amount': amount,
            'is_valid_mpesa': is_valid_mpesa,
            'is_complete_message': is_complete
        })

    return JsonResponse({'error': 'Image not provided'}, status=400)




############################################################
############################################################
#######  M-PESA STK Push and Callback Views ################
############################################################
############################################################
def generate_password():
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    data = BUSINESS_SHORTCODE + PASSKEY + timestamp
    password = base64.b64encode(data.encode()).decode()
    return password, timestamp

def get_access_token():
    response = requests.get(
        "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
        auth=(CONSUMER_KEY, CONSUMER_SECRET)
    )
    return response.json().get('access_token')

class STKNewPushView(APIView):
    permission_classes = [IsAuthenticated]  # Add authentication requirement
    
    def post(self, request):
        phone = request.data.get("phone_number")
        amount = request.data.get("amount")

        password, timestamp = generate_password()
        access_token = get_access_token()

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        payload = {
            "BusinessShortCode": BUSINESS_SHORTCODE,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": amount,
            "PartyA": phone,
            "PartyB": BUSINESS_SHORTCODE,
            "PhoneNumber": phone,
            "CallBackURL": CALLBACK_URL,
            "AccountReference": "Test",
            "TransactionDesc": "Payment"
        }

        response = requests.post(
            "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            json=payload, headers=headers
        )
        
        # Save user session after successful STK push
        if response.status_code == 200:
            response_data = response.json()
            checkout_request_id = response_data.get('CheckoutRequestID')
            merchant_request_id = response_data.get('MerchantRequestID')
            
            # Save user session
            try:
                UserPaymentSession.objects.create(
                    user=request.user,  # The logged-in user
                    checkout_request_id=checkout_request_id,
                    merchant_request_id=merchant_request_id
                )
                logger.info(f"✅ User session saved for {request.user.username}")
            except Exception as e:
                logger.error(f"❌ Failed to save user session: {str(e)}")
        
        return Response(response.json())


@method_decorator(csrf_exempt, name='dispatch')
class STKNewCallbackView(APIView):
    permission_classes = [AllowAny] 
    
    def post(self, request):
        data = request.data
        logger.info("📥 M-Pesa Callback Received:\n%s", data)

        callback = data.get('Body', {}).get('stkCallback', {})
        result_code = callback.get('ResultCode')
        result_desc = callback.get('ResultDesc')
        merchant_request_id = callback.get('MerchantRequestID')
        checkout_request_id = callback.get('CheckoutRequestID')

        # Find the user who initiated this payment
        user = None
        try:
            payment_session = UserPaymentSession.objects.get(
                checkout_request_id=checkout_request_id
            )
            user = payment_session.user
            logger.info(f"✅ Found user for payment: {user.username}")
        except UserPaymentSession.DoesNotExist:
            logger.warning(f"⚠️ No user session found for checkout_request_id: {checkout_request_id}")
        except Exception as e:
            logger.error(f"❌ Error finding user session: {str(e)}")

        if result_code == 0:  # Successful
            items = callback.get('CallbackMetadata', {}).get('Item', [])
            item_map = {item['Name']: item.get('Value') for item in items}

            transaction = MpesaNewTransaction.objects.create(
                user=user,  # Add the user who submitted the gig
                phone_number=item_map.get('PhoneNumber'),
                amount=item_map.get('Amount'),
                mpesa_receipt_number=item_map.get('MpesaReceiptNumber'),
                transaction_date=datetime.strptime(str(item_map.get('TransactionDate')), "%Y%m%d%H%M%S"),
                merchant_request_id=merchant_request_id,
                checkout_request_id=checkout_request_id,
                result_code=result_code,
                result_desc=result_desc,
                raw_callback=callback
            )
            return Response({"status": "success", "transaction": transaction.mpesa_receipt_number})
        else:
            # Optionally log failed transactions
            MpesaNewTransaction.objects.create(
                user=user,  # Add the user even for failed transactions
                phone_number="Unknown",
                amount=0,
                mpesa_receipt_number="FAILED",
                transaction_date=timezone.now(),
                merchant_request_id=merchant_request_id,
                checkout_request_id=checkout_request_id,
                result_code=result_code,
                result_desc=result_desc,  
                raw_callback=callback
            )
            return Response({"status": "failed", "reason": result_desc})


class MpesaMessagesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        transactions = MpesaNewTransaction.objects.all()

        # Optional filters
        phone_number = request.query_params.get('phone_number')
        amount = request.query_params.get('amount')
        receipt = request.query_params.get('mpesa_receipt_number')
        date_from = request.query_params.get('date_from')  # format: YYYY-MM-DD
        date_to = request.query_params.get('date_to')      # format: YYYY-MM-DD
        user_id = request.query_params.get('user_id')      # filter by specific user (optional)

        if phone_number:
            transactions = transactions.filter(phone_number=phone_number)
        if amount:
            transactions = transactions.filter(amount=amount)
        if receipt:
            transactions = transactions.filter(mpesa_receipt_number=receipt)
        if date_from:
            transactions = transactions.filter(transaction_date__gte=date_from)
        if date_to:
            transactions = transactions.filter(transaction_date__lte=date_to)
        if user_id:
            transactions = transactions.filter(user__id=user_id)

        transactions = transactions.order_by('-transaction_date')
        serializer = MpesaNewTransactionSerializer(transactions, many=True)

        return Response({
            "count": transactions.count(),
            "transactions": serializer.data
        }, status=status.HTTP_200_OK)
    




class UserMpesaMessagesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        transactions = MpesaNewTransaction.objects.filter(user=request.user)

        # Optional filters
        phone_number = request.query_params.get('phone_number')
        amount = request.query_params.get('amount')
        receipt = request.query_params.get('mpesa_receipt_number')
        date_from = request.query_params.get('date_from')  # format: YYYY-MM-DD
        date_to = request.query_params.get('date_to')      # format: YYYY-MM-DD

        if phone_number:
            transactions = transactions.filter(phone_number=phone_number)
        if amount:
            transactions = transactions.filter(amount=amount)
        if receipt:
            transactions = transactions.filter(mpesa_receipt_number=receipt)
        if date_from:
            transactions = transactions.filter(transaction_date__gte=date_from)
        if date_to:
            transactions = transactions.filter(transaction_date__lte=date_to)

        transactions = transactions.order_by('-transaction_date')
        serializer = MpesaNewTransactionSerializer(transactions, many=True)

        return Response({
            "count": transactions.count(),
            "user_id": request.user.id,
            "username": request.user.username,
            "transactions": serializer.data
        }, status=status.HTTP_200_OK)
    



    
###########################################################################
###########################################################################
####################END MPESA CIEWS HERE###################################
###########################################################################
###########################################################################


username = settings.AT_USERNAME
api_key = settings.AT_API_KEY  
africastalking.initialize(username, api_key)
sms = africastalking.SMS
@method_decorator(csrf_exempt, name='dispatch')
class SendOTPView(View):
    def post(self, request):
        try:
            # Parse JSON data from request body
            data = json.loads(request.body)
            phone_number = data.get("phone")
        except json.JSONDecodeError:
            # Fallback to form data if JSON parsing fails
            phone_number = request.POST.get("phone")

        if not phone_number:
            return JsonResponse({"status": "error", "message": "Phone number is required"}, status=400)

        # Generate a 6-digit OTP
        otp = str(random.randint(100000, 999999))
        message = f"Your Jenga Pro verification code is {otp}"

        try:
            # Send SMS to the real phone number
            response = sms.send(
                message,
                [phone_number],
                # Try without sender_id first, or use an approved one
                # sender_id="JENGAPRO"  # Comment this out temporarily
            )
            
            # Log the full response for debugging
            logger.info(f"Africa's Talking Response: {response}")
            print(f"Full AT Response: {response}")  # For immediate debugging
            
            # Parse the response to get more details
            sms_data = response.get('SMSMessageData', {})
            recipients = sms_data.get('Recipients', [])
            
            if recipients:
                recipient = recipients[0]
                status_code = recipient.get('statusCode')
                status = recipient.get('status')
                message_id = recipient.get('messageId')
                cost = recipient.get('cost')
                
                # Log recipient details
                logger.info(f"Status Code: {status_code}, Status: {status}, MessageID: {message_id}, Cost: {cost}")
                
                return JsonResponse({
                    "status": "success",
                    "otp": otp,
                    "at_response": response,
                    "recipient_status": status,
                    "status_code": status_code,
                    "message_id": message_id,
                    "cost": cost,
                    "debug_info": {
                        "phone_number": phone_number,
                        "message_length": len(message),
                        "username": username,
                        "has_sender_id": False  # Set to True if using sender_id
                    }
                })
            else:
                return JsonResponse({
                    "status": "error", 
                    "message": "No recipient data in response",
                    "at_response": response
                }, status=500)
                
        except Exception as e:
            logger.error(f"SMS sending failed: {str(e)}")
            return JsonResponse({
                "status": "error", 
                "message": str(e),
                "debug_info": {
                    "phone_number": phone_number,
                    "username": username,
                    "message": message
                }
            }, status=500)
        






# 1. Submit Verification (User uploads ID front, back, selfie)
class VerificationRequestCreateView(generics.CreateAPIView):
    serializer_class = VerificationRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        request = serializer.save(user=self.request.user)
        # link to user
        self.request.user.current_verification = request
        self.request.user.save()


# 2. Approve/Reject Verification (Admin only)
from rest_framework.views import APIView

class VerificationActionView(APIView):
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        """Approve or Reject verification"""
        try:
            verification = VerificationRequest.objects.get(pk=pk)
        except VerificationRequest.DoesNotExist:
            return Response({"error": "Not found"}, status=status.HTTP_404_NOT_FOUND)

        action = request.data.get("action")
        reason = request.data.get("reason", "")

        if action == "approve":
            verification.status = "approved"
            verification.user.is_verified = True
            verification.user.increase_score(20)  # e.g. +20 on approval
            verification.user.save()

        elif action == "reject":
            verification.status = "rejected"
            verification.rejection_reason = reason
            verification.user.is_verified = False
            verification.user.save()

        else:
            return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)

        verification.save()
        return Response(VerificationRequestSerializer(verification).data)


# 3. View Verifications
class VerificationRequestListView(generics.ListAPIView):
    serializer_class = VerificationRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:  # Admin can see all
            return VerificationRequest.objects.all()
        return VerificationRequest.objects.filter(user=user)

# user view for latest verification
class LatestVerificationView(generics.RetrieveAPIView):


    serializer_class = VerificationRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        latest_verification = (
            VerificationRequest.objects.filter(user=request.user)
            .order_by("-created_at")
            .first()
        )

        if not latest_verification:
            return Response({"detail": "No verification found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(latest_verification)
        return Response(serializer.data)
    




############################################
############################################
###############REPORTS VIEWS################
############################################
############################################



# 1. Weekly Worker Report
class WeeklyWorkerReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = (
            Gig.objects
            .annotate(year=ExtractYear("created_at"), week=ExtractWeek("created_at"))
            .values("year", "week")
            .annotate(
                total_workers=Count("worker", distinct=True),
                verified_workers=Count("worker", distinct=True, filter=Q(worker__is_verified=True)),
                unverified_workers=Count("worker", distinct=True, filter=Q(worker__is_verified=False)),
            )
            .order_by("-year", "-week")
        )
        data = [
            {
                "week": f"{row['year']}-W{row['week']}",
                "total_workers": row["total_workers"],
                "verified_workers": row["verified_workers"],
                "unverified_workers": row["unverified_workers"],
            }
            for row in qs
        ]
        return Response(WeeklyWorkerReportSerializer(data, many=True).data)


# 2. Weekly Gigs Report
class WeeklyGigReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = (
            Gig.objects
            .annotate(year=ExtractYear("created_at"), week=ExtractWeek("created_at"))
            .values("year", "week")
            .annotate(
                total_gigs=Count("id"),
                verified=Count("id", filter=Q(is_verified=True)),
                unverified=Count("id", filter=Q(is_verified=False)),
            )
            .order_by("-year", "-week")
        )
        data = [
            {
                "week": f"{row['year']}-W{row['week']}",
                "total_gigs": row["total_gigs"],
                "verified": row["verified"],
                "unverified": row["unverified"],
            }
            for row in qs
        ]
        return Response(WeeklyGigReportSerializer(data, many=True).data)


# 3. Job Type Distribution Report
class JobTypeDistributionReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = (
            Gig.objects
            .annotate(year=ExtractYear("created_at"), week=ExtractWeek("created_at"))
            .values("year", "week", "job_type__name")
            .annotate(count=Count("id"))
            .order_by("-year", "-week", "-count")
        )
        data = [
            {
                "week": f"{row['year']}-W{row['week']}",
                "job_type": row["job_type__name"],
                "count": row["count"],
            }
            for row in qs
        ]
        return Response(JobTypeDistributionSerializer(data, many=True).data)


# 4. Organization Performance Report
class OrgPerformanceReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = (
            Gig.objects
            .values("organization__name")
            .annotate(
                total_gigs=Count("id"),
                verified=Count("id", filter=Q(is_verified=True)),
            )
            .order_by("-total_gigs")
        )
        data = [
            {
                "organization": row["organization__name"],
                "total_gigs": row["total_gigs"],
                "verified": row["verified"],
            }
            for row in qs
        ]
        return Response(OrgPerformanceSerializer(data, many=True).data)


# 5. Verification Impact Report
class VerificationImpactReportView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        verified_workers = User.objects.filter(is_verified=True).annotate(gig_count=Count("gigs"))
        unverified_workers = User.objects.filter(is_verified=False).annotate(gig_count=Count("gigs"))

        data = {
            "verified_workers_count": verified_workers.count(),
            "verified_avg_gigs": verified_workers.aggregate(avg=Avg("gig_count"))["avg"] or 0,
            "unverified_workers_count": unverified_workers.count(),
            "unverified_avg_gigs": unverified_workers.aggregate(avg=Avg("gig_count"))["avg"] or 0,
        }
        return Response(VerificationImpactSerializer(data).data)
    




##############################################################
##############################################################
##########  SINGLE USER GIGS AND HISTORY VIEWS ###############
##############################################################
##############################################################

# 1. Gig count analysis
class GigCountAnalysisView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_orgs = Organization.objects.filter(owner=request.user)
        gigs = Gig.objects.filter(organization__in=user_orgs)

        period = request.query_params.get("period", "week")

        if period == "day":
            start_date = now().date() - timedelta(days=1)
        elif period == "month":
            start_date = now().date() - timedelta(days=30)
        elif period == "year":
            start_date = now().date() - timedelta(days=365)
        else:  # default week
            start_date = now().date() - timedelta(days=7)

        count = gigs.filter(start_date__gte=start_date).count()
        data = {"period": period, "total_gigs": count}
        return Response(GigCountSerializer(data).data)


# 2. Gig completion rate
class GigCompletionRateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # All orgs owned by the user
        user_orgs = Organization.objects.filter(owner=request.user)

        # Current gigs
        gigCurrents = Gig.objects.filter(organization__in=user_orgs)

        # Completed gigs (automatically in history)
        gigHist = GigHistory.objects.filter(organization__in=user_orgs)

        total = gigCurrents.count() + gigHist.count()
        completed = gigHist.count()
        rate = (completed / total * 100) if total > 0 else 0

        data = {
            "total_gigs": total,
            "completed_gigs": completed,
            "completion_rate": round(rate, 2),
        }
        return Response(data)


# 3. Total revenue per period
class GigRevenueAnalysisView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_orgs = Organization.objects.filter(owner=request.user)
        gigs = Gig.objects.filter(organization__in=user_orgs)

        period = request.query_params.get("period", "week")

        if period == "day":
            start_date = now().date() - timedelta(days=1)
        elif period == "month":
            start_date = now().date() - timedelta(days=30)
        elif period == "year":
            start_date = now().date() - timedelta(days=365)
        else:  # default week
            start_date = now().date() - timedelta(days=7)

        total = gigs.filter(start_date__gte=start_date).aggregate(
            total=Sum("amount_paid")
        )["total"] or 0

        data = {"period": period, "total_revenue": total}
        return Response(GigRevenueSerializer(data).data)


# 4. Gig trends (weekly, monthly, yearly)
class GigTrendsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        period = request.query_params.get("period", "week")
        user_orgs = Organization.objects.filter(owner=request.user)
        gigs = Gig.objects.filter(organization__in=user_orgs, is_complete=True)

        if period == "week":
            grouping = TruncWeek("start_date")
        elif period == "month":
            grouping = TruncMonth("start_date")
        elif period == "year":
            grouping = TruncYear("start_date")
        else:
            return Response(
                {"error": "Invalid period. Use week, month, or year."}, status=400
            )

        trends = (
            gigs.annotate(period=grouping)
            .values("period")
            .annotate(completed_gigs=Count("id"))
            .order_by("period")
        )

        return Response(GigTrendsSerializer(trends, many=True).data)


# 5. Top earning gigs
class TopEarningGigsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_orgs = Organization.objects.filter(owner=request.user)
        gigs = Gig.objects.filter(organization__in=user_orgs)

        top_gigs = (
            gigs.values("job_type__name", "client_name")
            .annotate(revenue=Sum("amount_paid"))
            .order_by("-revenue")[:5]
        )

        data = [
            {
                "gig_title": g["job_type__name"] or g["client_name"] or "Unknown",
                "revenue": g["revenue"],
            }
            for g in top_gigs
        ]
        return Response(TopGigsSerializer(data, many=True).data)