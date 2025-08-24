from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken  
from .models import  CreditScoreHistory, User,Gig,JobType,Payment,GigHistory,Organization,MpesaNewTransaction, VerificationRequest, GigsAvailable  # use your custom user model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'account_type', 'full_name', 'national_id']  

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("Email already in use.")
        return value

    def validate_username(self, value):
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("Username already in use.")
        return value

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()



class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        token['account_type'] = user.account_type  # Add this line

        return token
    

# app/serializers.py
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['full_name', 'national_id', 'location', 'phone', 'profile_pic']

class GigSerializer(serializers.ModelSerializer):
    class Meta:
        model = Gig
        fields = '__all__'
        read_only_fields = ['worker', 'logged_by', 'verified_by', 'is_verified', 'created_at']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'phone', 'full_name', 'national_id',   'county', 'constituency', 'ward', 'profile_pic','is_verified','credit_score','current_verification']  

    def validate_phone(self, value):
        user = self.instance  # the currently authenticated user
        if User.objects.filter(phone__iexact=value).exclude(pk=user.pk).exists():
            raise serializers.ValidationError("Phone number is already in use.")
        return value
        
class JobTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobType
        fields = ['id', 'name', 'code']
        read_only_fields = ['code']


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'
        read_only_fields = ['user', 'payment_date', 'is_confirmed']



class GigHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = GigHistory
        fields = '__all__'
        read_only_fields = ['worker']



class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'
        read_only_fields = ['owner', 'created_at']

class CreditScoreHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = CreditScoreHistory
        fields = ["id", "change", "new_score", "action", "timestamp"]

class UserDetailWithGigsSerializer(serializers.ModelSerializer):
    gigs = GigSerializer(many=True, read_only=True)  # worker gigs
    logged_gigs = GigSerializer(many=True, read_only=True)  # gigs logged by this user

    class Meta:
        model = User
        fields = [
            "id", "username", "full_name", "email", "phone",
            "county", "constituency", "ward",
            "is_verified", "credit_score",
            "gigs", "logged_gigs"
        ]

    def get_gigs(self, obj):
        gigs = Gig.objects.filter(worker=obj)
        return GigSerializer(gigs, many=True).data

    def get_gig_history(self, obj):
        history = GigHistory.objects.filter(worker=obj)  
        return GigHistorySerializer(history, many=True).data  
    


class MpesaNewTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = MpesaNewTransaction
        fields = '__all__'



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'username', 'full_name', 'email', 'phone', 'account_type',
            'location', 'national_id', 'profile_pic'
        ]


class VerificationRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = VerificationRequest
        fields = [
            "id", "user", "status",
            "id_front", "id_back", "selfie",
            "rejection_reason", "created_at", "updated_at"
        ]
        read_only_fields = ["user", "status", "created_at", "updated_at", "rejection_reason"]


class GigsAvailableSerializer(serializers.ModelSerializer):
    class Meta:
        model = GigsAvailable
        fields = ['id', 'title', 'description', 'county','constituency','ward', 'created_at', 'organization', 'worker']
        read_only_fields = ['id', 'created_at', 'organization', 'worker']


# ########################################
#########################################
##########  REPORTS SERIALIZERS ##########
#########################################
#########################################   


# 1. Weekly Worker Report
class WeeklyWorkerReportSerializer(serializers.Serializer):
    week = serializers.CharField()
    total_workers = serializers.IntegerField()
    verified_workers = serializers.IntegerField()
    unverified_workers = serializers.IntegerField()


# 2. Weekly Gigs Report
class WeeklyGigReportSerializer(serializers.Serializer):
    week = serializers.CharField()
    total_gigs = serializers.IntegerField()
    verified = serializers.IntegerField()
    unverified = serializers.IntegerField()


# 3. Job Type Distribution Report
class JobTypeDistributionSerializer(serializers.Serializer):
    week = serializers.CharField()
    job_type = serializers.CharField()
    count = serializers.IntegerField()


# 4. Organization Performance Report
class OrgPerformanceSerializer(serializers.Serializer):
    organization = serializers.CharField()
    total_gigs = serializers.IntegerField()
    verified = serializers.IntegerField()


# 5. Verification Impact Report
class VerificationImpactSerializer(serializers.Serializer):
    verified_workers_count = serializers.IntegerField()
    verified_avg_gigs = serializers.FloatField()
    unverified_workers_count = serializers.IntegerField()
    unverified_avg_gigs = serializers.FloatField()



##############################################################
##############################################################
##########  SINGLE USER GIGS AND HISTORY SERIALIZERS ##########
##############################################################
##############################################################

class GigCountSerializer(serializers.Serializer):
    period = serializers.CharField()
    total_gigs = serializers.IntegerField()

class GigCompletionRateSerializer(serializers.Serializer):
    total_gigs = serializers.IntegerField()
    completed_gigs = serializers.IntegerField()
    completion_rate = serializers.FloatField()

class GigRevenueSerializer(serializers.Serializer):
    period = serializers.CharField()
    total_revenue = serializers.DecimalField(max_digits=12, decimal_places=2)

class GigTrendsSerializer(serializers.Serializer):
    week = serializers.CharField()
    completed_gigs = serializers.IntegerField()

class TopGigsSerializer(serializers.Serializer):
    gig_title = serializers.CharField()
    revenue = serializers.DecimalField(max_digits=12, decimal_places=2)

