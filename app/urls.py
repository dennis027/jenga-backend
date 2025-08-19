from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from .views import LatestVerificationView, RegisterView, LoginView, LogoutView, CookieLoginView , ProfileUpdateView, LogGigView, UserOrganizationGigListView, VerificationActionView, VerificationRequestCreateView, VerificationRequestListView, VerifyGigView,GigListView,UserProfileView,JobTypeListCreateView,JobTypeDeleteView,PaymentUploadView,LoggedByUserGigListView,GigHistoryView,UserGigHistoryView,CheckEmailExists,CheckUsernameExists,CheckPhoneExists, STKNewPushView, STKNewCallbackView,OrganizationListCreateView,OrganizationDetailUpdateView, OrganizationSoftDeleteView,WorkerSearchAPIView,VerifyResetCodeView,ConfirmResetPasswordView,RequestPasswordResetView,MpesaMessagesAPIView,UserMpesaMessagesAPIView,GigSearchView,UserListAPIView,ActivateAccountAPIView,ResendVerificationEmailView,SendOTPView,CompleteGigAPIView,WeeklyWorkerReportView,WeeklyGigReportView,JobTypeDistributionReportView,OrgPerformanceReportView,UserOrganizationListCreateView, VerificationImpactReportView, OrganizationGigsAPIView,activation_success_view ,activation_failed_view ,extract_transaction_code  
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import TemplateView

urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register'),


    # check if email, username or phone exists
    path('api/check-email/', CheckEmailExists.as_view(), name='check-email'),
    path('api/check-username/', CheckUsernameExists.as_view(), name='check-username'),
    path('api/check-phone/', CheckPhoneExists.as_view(), name='check-phone'),


    # verification and activation
    path('api/activate/<uidb64>/<token>/', ActivateAccountAPIView.as_view(), name='activate'),
    path('api/resend-verification/', ResendVerificationEmailView.as_view(), name='resend-verification'),
    path("send-otp/", SendOTPView.as_view(), name="send-otp"),
    path('activation-success/', activation_success_view, name='activation-success'),
    path('activation-failed/', activation_failed_view, name='activation-failed'),


    # login and logout
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/logout/', LogoutView.as_view(), name='logout'),


    # password reset
    path('api/request-password-reset/', RequestPasswordResetView.as_view()),
    path('api/password-reset/verify/', VerifyResetCodeView.as_view()),
    path('api/password-reset/confirm/', ConfirmResetPasswordView.as_view()),
    path('api/csrf-token/', views.csrf_token_view, name='csrf_token'),
    path('api/login-cookie/', CookieLoginView.as_view(), name='login-cookie'),

    # user profile and updates
    path('api/profile/', ProfileUpdateView.as_view(), name='profile-update'),
    path('api/list-users/', UserListAPIView.as_view(), name='user-list'),
    path('api/user/', UserProfileView.as_view(), name='user-profile'), 

    # gig related URLs
    path('api/gigs/', LogGigView.as_view(), name='log-gig'),
    path('api/gigs/verify/<int:gig_id>/', VerifyGigView.as_view(), name='verify-gig'), 
    path('gigs/<int:gig_id>/complete/', CompleteGigAPIView.as_view(), name='complete-gig'),
    path('api/gigs-list/', GigListView.as_view(), name='gig-list'),
    path('api/user-gigs-list/', UserOrganizationGigListView.as_view(), name='gig-list'),
    path('api/job-types/', JobTypeListCreateView.as_view(), name='list_create_job_types'),
    path('api/job-types/<int:pk>/', JobTypeDeleteView.as_view(), name='delete_job_type'),
    path('api/user-gigs/', LoggedByUserGigListView.as_view(), name='user-gigs'),
    path('api/search-gigs/', GigSearchView.as_view(), name='search-gigs'),
    path('api/upload-payment/', PaymentUploadView.as_view(), name='upload_payment'),
    path('api/user-work-history/', UserGigHistoryView.as_view(), name='my-work-history'),
  

    # organization URLs
    path('api/organizations/', OrganizationListCreateView.as_view(), name='organization-list-create'),
    path('api/user-organizations/', UserOrganizationListCreateView.as_view(), name='organization-list-create'),
    path('api/organizations/<int:pk>/', OrganizationDetailUpdateView.as_view(), name='organization-detail-update'),
    path('api/organizations/<int:pk>/toggle-active/', OrganizationSoftDeleteView.as_view(), name='organization-soft-delete'),
    path('api/organizations/<int:org_id>/gigs/', OrganizationGigsAPIView.as_view(), name='organization-gigs'),


    path('api/workers/search/', WorkerSearchAPIView.as_view(), name='worker-search'),
    path('api/extract-code/', extract_transaction_code, name='extract_code'),  

    # ID VERIFICATION
    path("api/verification/submit/", VerificationRequestCreateView.as_view(), name="verification-submit"),
    path("api/verification/<int:pk>/action/", VerificationActionView.as_view(), name="verification-action"),
    path("api/verification/list/", VerificationRequestListView.as_view(), name="verification-list"),
    path("api/verification/latest/", LatestVerificationView.as_view(), name="verification-latest"),


    #mpesa view
    path('api/stk-new-push/', STKNewPushView.as_view()),
    path('api/stk-new-callback/', STKNewCallbackView.as_view()),
    path('api/mpesa-messages/', MpesaMessagesAPIView.as_view(), name='mpesa-messages'),
    path('api/single-messages/', UserMpesaMessagesAPIView.as_view(), name='all-mpesa-messages'),



    # many reports
    path("api/reports/weekly-workers/", WeeklyWorkerReportView.as_view(), name="weekly-workers-report"),
    path("api/reports/weekly-gigs/", WeeklyGigReportView.as_view(), name="weekly-gigs-report"),
    path("api/reports/job-type-distribution/", JobTypeDistributionReportView.as_view(), name="job-type-distribution"),
    path("api/reports/org-performance/", OrgPerformanceReportView.as_view(), name="org-performance"),
    path("api/reports/verification-impact/", VerificationImpactReportView.as_view(), name="verification-impact"),


] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
  