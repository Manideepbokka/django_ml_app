from django.urls import path
from .views import RegisterView, LoginView, predict_view , ForgotPasswordView, ResetPasswordView, ChangePasswordView, ResendOTPView, HistoryView, ValidateOTPView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('validate-otp/', ValidateOTPView.as_view(), name='validate_otp'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path("predict/", predict_view, name="predict"),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),                
    path('history/', HistoryView.as_view(), name='history'),
]
