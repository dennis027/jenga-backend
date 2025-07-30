from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate,get_user_model
from .serializers import RegisterSerializer, LoginSerializer, SuccessfulMpesaTransactionSerializer, UserProfileSerializer,GigSerializer,JobTypeSerializer, PaymentSerializer,GigHistorySerializer, MpesaTransactionSerializer,OrganizationSerializer,UserDetailWithGigsSerializer
from rest_framework import status, permissions,generics
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils.timezone import now
from datetime import timedelta
from rest_framework.permissions import IsAuthenticated
from .models import Gig,JobType,Payment,GigHistory, MpesaTransaction, SuccessfulMpesaTransaction, Organization
from rest_framework.parsers import MultiPartParser, FormParser,JSONParser
from django.db.models import Q 
from .utils import lipa_na_mpesa
import json
import logging
import json
from rest_framework.parsers import JSONParser
from django.utils.dateparse import parse_datetime
from datetime import datetime
from django.utils import timezone
from rest_framework.authentication import TokenAuthentication  # or JWT
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny



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
    

class STKPushView(APIView):
    def post(self, request):
        phone = request.data.get("phone")
        amount = request.data.get("amount")

        if not phone or not amount:
            return Response({"error": "Phone and amount are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            response = lipa_na_mpesa(phone, amount)
            print(response)  # Debugging line to see the response
            # Save transaction
            MpesaTransaction.objects.create(
                phone=phone,
                amount=amount,
                merchant_request_id=response.get("MerchantRequestID"),
                checkout_request_id=response.get("CheckoutRequestID"),
                response_code=response.get("ResponseCode"),
                response_description=response.get("ResponseDescription"),
                customer_message=response.get("CustomerMessage"),
            )

            return Response(response)
        except Exception as e:
            logger.error(str(e))
            return Response({"error": "Something went wrong"}, status=500)
        


class MPESACallbackView(APIView):
    def post(self, request):
        try:
            # 🔍 Log full raw request for debugging
            logger.info("🔥 M-Pesa Raw Callback:\n%s", json.dumps(request.data, indent=2))

            callback = request.data.get("Body", {}).get("stkCallback", {})
            result_code = callback.get("ResultCode")
            result_desc = callback.get("ResultDesc")
            merchant_request_id = callback.get("MerchantRequestID")
            checkout_request_id = callback.get("CheckoutRequestID")

            metadata = callback.get("CallbackMetadata", {}).get("Item", [])

            # ❗️Handle case where metadata is missing
            if not metadata:
                logger.warning("⚠️ CallbackMetadata missing or empty. Skipping transaction save.")
                return Response({"ResultCode": 0, "ResultDesc": "No data to process."})

            # 🧠 Convert list of metadata items into a dictionary
            data = {item['Name']: item.get('Value') for item in metadata}

            phone = str(data.get("PhoneNumber", ""))
            amount = data.get("Amount", 0)
            mpesa_receipt_number = data.get("MpesaReceiptNumber", "")
            transaction_date_str = str(data.get("TransactionDate", ""))
            transaction_date = timezone.now()

            # ⏰ Parse Safaricom's timestamp format
            try:
                if transaction_date_str and len(transaction_date_str) == 14:
                    transaction_date = datetime.strptime(transaction_date_str, "%Y%m%d%H%M%S")
            except Exception as e:
                logger.warning("⚠️ Failed to parse transaction date: %s", str(e))

            # ✅ Save successful transaction if not already recorded
            if result_code == 0 and mpesa_receipt_number:
                if not SuccessfulMpesaTransaction.objects.filter(mpesa_receipt_number=mpesa_receipt_number).exists():
                    SuccessfulMpesaTransaction.objects.create(
                        phone=phone,
                        amount=amount,
                        mpesa_receipt_number=mpesa_receipt_number,
                        transaction_date=transaction_date,
                        merchant_request_id=merchant_request_id,
                        checkout_request_id=checkout_request_id
                    )
                    logger.info("✅ Successful M-Pesa transaction saved.")
                else:
                    logger.info("ℹ️ Transaction already exists.")
            else:
                logger.warning("⚠️ Transaction not successful or missing receipt number.")

        except Exception as e:
            logger.error("❌ Error processing M-Pesa callback: %s", str(e))

        # Always respond to Safaricom with ResultCode 0
        return Response({"ResultCode": 0, "ResultDesc": "Accepted"})
    



    
class MpesaTransactionListView(APIView):
    def get(self, request):
        transactions = MpesaTransaction.objects.all().order_by('-created_at')
        serializer = MpesaTransactionSerializer(transactions, many=True)
        return Response(serializer.data)
    


class SuccessfulMpesaTransactionListView(generics.ListAPIView):
    queryset = SuccessfulMpesaTransaction.objects.all().order_by('-transaction_date')
    serializer_class = SuccessfulMpesaTransactionSerializer



# organization model

class OrganizationListCreateView(generics.ListCreateAPIView):
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Organization.objects.filter(owner=self.request.user, is_active=True)

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
    def get(self, request, *args, **kwargs):
        query = request.query_params.get('q', None)

        if not query:
            return Response({"error": "Please provide a search query (?q=)"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(
                Q(username__iexact=query) |
                Q(email__iexact=query) |
                Q(phone__iexact=query)
            )
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        data = UserDetailWithGigsSerializer(user).data
        return Response(data, status=status.HTTP_200_OK)