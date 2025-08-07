import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate,get_user_model
from .serializers import RegisterSerializer, LoginSerializer, UserProfileSerializer,GigSerializer,JobTypeSerializer, PaymentSerializer,GigHistorySerializer,OrganizationSerializer,UserSerializer,UserDetailWithGigsSerializer,MpesaNewTransactionSerializer
from rest_framework import status, permissions,generics
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils.timezone import now
from datetime import timedelta
from rest_framework.permissions import IsAuthenticated
from .models import Gig,JobType,GigHistory, Organization,MpesaNewTransaction,UserPaymentSession
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
    


# organization model

class OrganizationListCreateView(generics.ListCreateAPIView):
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Organization.objects.all().order_by("id")

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
