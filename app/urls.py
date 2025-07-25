from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from .views import RegisterView, LoginView, LogoutView, CookieLoginView , ProfileUpdateView, LogGigView, SuccessfulMpesaTransactionListView, VerifyGigView,GigListView,UserProfileView,JobTypeListCreateView,JobTypeDeleteView,PaymentUploadView,LoggedByUserGigListView,GigHistoryView,UserGigHistoryView,CheckEmailExists,CheckUsernameExists,CheckPhoneExists,STKPushView, MPESACallbackView,MpesaTransactionListView,OrganizationListCreateView,OrganizationDetailUpdateView, OrganizationSoftDeleteView,WorkerSearchAPIView


urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/login-cookie/', CookieLoginView.as_view(), name='login-cookie'),
    path('api/profile/', ProfileUpdateView.as_view(), name='profile-update'),
    path('api/gigs/', LogGigView.as_view(), name='log-gig'),
    path('api/gigs/verify/<int:gig_id>/', VerifyGigView.as_view(), name='verify-gig'), 
    path('api/gigs-list/', GigListView.as_view(), name='gig-list'),
    path('api/user/', UserProfileView.as_view(), name='user-profile'),
    path('api/job-types/', JobTypeListCreateView.as_view(), name='list_create_job_types'),
    path('api/job-types/<int:pk>/', JobTypeDeleteView.as_view(), name='delete_job_type'),
    path('api/user-gigs/', LoggedByUserGigListView.as_view(), name='user-gigs'),
    path('api/upload-payment/', PaymentUploadView.as_view(), name='upload_payment'),
    path('api/work-history/', GigHistoryView.as_view(), name='work-history'),
    path('api/user-work-history/', UserGigHistoryView.as_view(), name='my-work-history'),
    path('api/check-email/', CheckEmailExists.as_view(), name='check-email'),
    path('api/check-username/', CheckUsernameExists.as_view(), name='check-username'),
    path('api/check-phone/', CheckPhoneExists.as_view(), name='check-phone'),
    path("api/stk-push/", STKPushView.as_view(), name="stk_push"),
    path("api/callback/", MPESACallbackView.as_view(), name="mpesa_callback"),
    path('api/transactions/', MpesaTransactionListView.as_view(), name='transaction_list'),
    path('api/successful-transactions/', SuccessfulMpesaTransactionListView.as_view(), name='successful-transactions'),
    path('api/organizations/', OrganizationListCreateView.as_view(), name='organization-list-create'),
    path('api/organizations/<int:pk>/', OrganizationDetailUpdateView.as_view(), name='organization-detail-update'),
    path('api/organizations/<int:pk>/toggle-active/', OrganizationSoftDeleteView.as_view(), name='organization-soft-delete'),
    path('api/workers/search/', WorkerSearchAPIView.as_view(), name='worker-search'),

]
  