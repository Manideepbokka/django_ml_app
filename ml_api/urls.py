from django.urls import path
from .views import RegisterView, LoginView, predict_view ,DistinctValuesView, PaginatedEmissionsView, ForgotPasswordView, ResetPasswordView, ChangePasswordView, ResendOTPView, HistoryView, ValidateOTPView,CookieTokenRefreshView,LogoutView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token-refresh/', CookieTokenRefreshView.as_view(), name='token_refresh'),
    path('validate-otp/', ValidateOTPView.as_view(), name='validate_otp'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path("predict/", predict_view, name="predict"),
    path("pagination-emissions", PaginatedEmissionsView.as_view(), name='paginated_emissions'),
    path('distinct-values', DistinctValuesView.as_view(), name='distinct_values'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),                
    path('history/', HistoryView.as_view(), name='history'),
    path('logout/', LogoutView.as_view(), name='logout' )
]
