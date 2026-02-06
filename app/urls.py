from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from .views import ContractorComparativeAnalyticsView, ContractorGigTrendsView, ContractorJobTypeAnalyticsView, ContractorLocationAnalyticsView, ContractorOrganizationPerformanceView, ContractorRevenueAnalyticsView, ContractorSummaryDashboardView, ContractorVerificationMetricsView, ContractorWorkerPerformanceView, ContractorWorkerRetentionView, CreditScoreHistoryView, FundiComparativeAnalyticsView, FundiCreditScoreAnalyticsView, FundiEarningsAnalyticsView, FundiJobTypeAnalyticsView, FundiLocationAnalyticsView, FundiOrganizationPerformanceView, FundiRecentWorkLogsView, FundiSummaryDashboardView, FundiVerificationMetricsView, FundiWorkConsistencyView, FundiWorkTrendsView, GigCompletionRateView, GigCountAnalysisView, GigRevenueAnalysisView, GigTrendsView, GigsAvailableListCreateView, LatestVerificationView, RegisterView, LoginView, LogoutView, CookieLoginView , ProfileUpdateView, LogGigView, TopEarningGigsView, UserOrganizationGigListView, VerificationActionView, VerificationRequestCreateView, VerificationRequestListView, VerifyGigView,GigListView,UserProfileView,JobTypeListCreateView,JobTypeDeleteView,PaymentUploadView,LoggedByUserGigListView,UserGigHistoryView,CheckEmailExists,CheckUsernameExists,CheckPhoneExists, STKNewPushView, STKNewCallbackView,OrganizationListCreateView,OrganizationDetailUpdateView, OrganizationSoftDeleteView,WorkerSearchAPIView,VerifyResetCodeView,ConfirmResetPasswordView,RequestPasswordResetView,MpesaMessagesAPIView,UserMpesaMessagesAPIView,GigSearchView,UserListAPIView,ActivateAccountAPIView,ResendVerificationEmailView,SendOTPView,CompleteGigAPIView,WeeklyWorkerReportView,WeeklyGigReportView,JobTypeDistributionReportView,Fundi30DayCalendarView,OrgPerformanceReportView,UserOrganizationListCreateView,FundiAllGigsView,FundiDashboardStatsView, VerificationImpactReportView,FundiCreditScoreHistoryView,FundiOrganizationsWorkedView, OrganizationGigsAPIView,activation_success_view ,activation_failed_view ,extract_transaction_code  ,ContractorDashboardStatsView,ContractorRecentGigsView,ContractorWeeklyChartView,ContractorTopSitesView,ContractorTopWorkersView,Contractor7DayCalendarView,ContractorOrganizationsView,ContractorGigsByOrganizationView,ContractorUnverifiedGigsView
from . import views
from django.conf import settings
from django.conf.urls.static import static

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
    path('api/gigs/<int:gig_id>/complete/', CompleteGigAPIView.as_view(), name='complete-gig'),
    path('api/gigs-list/', GigListView.as_view(), name='gig-list'),
    path('api/org-gigs-list/', UserOrganizationGigListView.as_view(), name='gig-list'),
    path('api/job-types/', JobTypeListCreateView.as_view(), name='list_create_job_types'),
    path('api/job-types/<int:pk>/', JobTypeDeleteView.as_view(), name='delete_job_type'),
    path('api/user-gigs/', LoggedByUserGigListView.as_view(), name='user-gigs'),
    path('api/search-gigs/', GigSearchView.as_view(), name='search-gigs'),
    path('api/upload-payment/', PaymentUploadView.as_view(), name='upload_payment'),
    path('api/user-work-history/', UserGigHistoryView.as_view(), name='my-work-history'),
    path('api/gigs-available/', GigsAvailableListCreateView.as_view(), name='gig-list-create'),
    path('api/credit-history/', CreditScoreHistoryView.as_view(), name='credit-history'),
  

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



    # Supervisor user reports analytics
    path("api/analysis/gig-count/", GigCountAnalysisView.as_view(), name="gig-count"),
    path("api/analysis/completion-rate/", GigCompletionRateView.as_view(), name="completion-rate"),
    path("api/analysis/revenue/", GigRevenueAnalysisView.as_view(), name="gig-revenue"),
    path("api/analysis/trends/", GigTrendsView.as_view(), name="gig-trends"),
    path("api/analysis/top-gigs/", TopEarningGigsView.as_view(), name="top-gigs"),


    # fundi dashboard

    path('api/fundi/dashboard/stats/', FundiDashboardStatsView.as_view(), name='fundi-dashboard-stats'),
    path('api/fundi/dashboard/recent-work/', FundiRecentWorkLogsView.as_view(), name='fundi-recent-work'),
    path('api/fundi/dashboard/calendar/', Fundi30DayCalendarView.as_view(), name='fundi-calendar'),
    path('api/fundi/dashboard/credit-history/', FundiCreditScoreHistoryView.as_view(), name='fundi-credit-history'),
    path('api/fundi/dashboard/all-gigs/', FundiAllGigsView.as_view(), name='fundi-all-gigs'),
    path('api/fundi/dashboard/organizations/', FundiOrganizationsWorkedView.as_view(), name='fundi-organizations'),

    # jenga dashboard
    path('api/contractor/dashboard/stats/', ContractorDashboardStatsView.as_view(), name='contractor-dashboard-stats'),
    path('api/contractor/dashboard/recent-gigs/', ContractorRecentGigsView.as_view(), name='contractor-recent-gigs'),
    path('api/contractor/dashboard/weekly-chart/', ContractorWeeklyChartView.as_view(), name='contractor-weekly-chart'),
    path('api/contractor/dashboard/top-sites/', ContractorTopSitesView.as_view(), name='contractor-top-sites'),
    path('api/contractor/dashboard/top-workers/', ContractorTopWorkersView.as_view(), name='contractor-top-workers'),
    path('api/contractor/dashboard/calendar/', Contractor7DayCalendarView.as_view(), name='contractor-calendar'),
    path('api/contractor/organizations/', ContractorOrganizationsView.as_view(), name='contractor-organizations'),
    path('api/contractor/organizations/<int:org_id>/gigs/', ContractorGigsByOrganizationView.as_view(), name='contractor-org-gigs'),
    path('api/contractor/dashboard/unverified-gigs/', ContractorUnverifiedGigsView.as_view(), name='contractor-unverified-gigs'),


        # Jenga  Analytics APIs
    path('api/contractor/analytics/gig-trends/', ContractorGigTrendsView.as_view(), name='analytics-gig-trends'),
    path('api/contractor/analytics/worker-performance/', ContractorWorkerPerformanceView.as_view(), name='analytics-worker-performance'),
    path('api/contractor/analytics/job-types/', ContractorJobTypeAnalyticsView.as_view(), name='analytics-job-types'),
    path('api/contractor/analytics/organization-performance/', ContractorOrganizationPerformanceView.as_view(), name='analytics-org-performance'),
    path('api/contractor/analytics/revenue/', ContractorRevenueAnalyticsView.as_view(), name='analytics-revenue'),
    path('api/contractor/analytics/location/', ContractorLocationAnalyticsView.as_view(), name='analytics-location'),
    path('api/contractor/analytics/verification/', ContractorVerificationMetricsView.as_view(), name='analytics-verification'),
    path('api/contractor/analytics/worker-retention/', ContractorWorkerRetentionView.as_view(), name='analytics-retention'),
    path('api/contractor/analytics/comparative/', ContractorComparativeAnalyticsView.as_view(), name='analytics-comparative'),
    path('api/contractor/analytics/summary/', ContractorSummaryDashboardView.as_view(), name='analytics-summary'),

    #FUNDI Pro 

    path('api/fundi/analytics/work-trends/', FundiWorkTrendsView.as_view(), name='fundi-analytics-work-trends'),
    path('api/fundi/analytics/organization-performance/', FundiOrganizationPerformanceView.as_view(), name='fundi-analytics-org-performance'),
    path('api/fundi/analytics/job-types/', FundiJobTypeAnalyticsView.as_view(), name='fundi-analytics-job-types'),
    path('api/fundi/analytics/credit-score/', FundiCreditScoreAnalyticsView.as_view(), name='fundi-analytics-credit-score'),
    path('api/fundi/analytics/earnings/', FundiEarningsAnalyticsView.as_view(), name='fundi-analytics-earnings'),
    path('api/fundi/analytics/location/', FundiLocationAnalyticsView.as_view(), name='fundi-analytics-location'),
    path('api/fundi/analytics/verification/', FundiVerificationMetricsView.as_view(), name='fundi-analytics-verification'),
    path('api/fundi/analytics/work-consistency/', FundiWorkConsistencyView.as_view(), name='fundi-analytics-consistency'),
    path('api/fundi/analytics/comparative/', FundiComparativeAnalyticsView.as_view(), name='fundi-analytics-comparative'),
    path('api/fundi/analytics/summary/', FundiSummaryDashboardView.as_view(), name='fundi-analytics-summary'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
  