from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from .utils import predict_all
from .models import PredictionLog
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.permissions import AllowAny
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db import transaction
import random
import jwt
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication


@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')

        # Validate email
        try:
            validate_email(email)
        except ValidationError:
            return Response({"error": "Invalid email address"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if username or email already exists
        if User.objects.filter(username=username).exists():
            return Response({"error": "User with this username already exists"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({"error": "User with this email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Use transaction.atomic to ensure atomicity
        try:
            with transaction.atomic():
                # Create user
                user = User.objects.create_user(
                    username=username,
                    password=password,
                    email=email,
                    first_name=first_name,
                    last_name=last_name
                )
                return Response({"message": "User registered successfully!"}, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(f"Error during registration: {e}")
            return Response({"error": "Internal server error. Registration failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)

        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def predict_view(request):
    try:
        with transaction.atomic():
            # Extract JWT token from request headers
            jwt_token = request.headers.get("Authorization").split(" ")[1]  # Bearer <token>
            decoded_token = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_token.get("user_id")

            if not user_id:
                return Response({"error": "User ID not found in token"}, status=400)

            # Get input data from the request
            input_data = request.data.get("inputData", {})
            print("Received Input Data:", input_data)

            # Validate required fields
            if not all(key in input_data for key in ["Age", "Speed", "Vehicle Type", "Fuel Type"]):
                return Response({"error": "Invalid input format. Required fields: Age, Speed, Vehicle Type, Fuel Type"}, status=400)

            print("Validated Input Data:", input_data)

            # Perform prediction
            predictions = predict_all(input_data)
            print("Generated Predictions:", predictions)

            # Save the prediction log to the database
            PredictionLog.objects.create(
                user_id=user_id,
                age=input_data["Age"],
                speed=input_data["Speed"],
                vehicle_type=input_data["Vehicle Type"],
                fuel_type=input_data["Fuel Type"],
                ga_co2=predictions["gaCo2"],
                ga_total_energy_rate=predictions["gaTotalEnergyRate"],
                ga_nox=predictions["gaNOx"],
                ga_pm25_brake_wear=predictions["gaPM2.5BrakeWear"],
                ga_pm25_tire_wear=predictions["gaPM2.5TireWear"],
            )

            # Prepare response
            response = {
                "gaCo2": predictions["gaCo2"],
                "gaTotalEnergyRate": predictions["gaTotalEnergyRate"],
                "gaNOx": predictions["gaNOx"],
                "gaPM2.5BrakeWear": predictions["gaPM2.5BrakeWear"],
                "gaPM2.5TireWear": predictions["gaPM2.5TireWear"],
            }

            return Response(response, status=200)
    except jwt.ExpiredSignatureError:
        return Response({"error": "JWT token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return Response({"error": "Invalid JWT token"}, status=401)
    except Exception as e:
        print(e)
        return Response({"error": str(e)}, status=400)


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')

        # Check if the email exists
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User with this email does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate OTP
        otp = random.randint(100000, 999999)

        try:
            with transaction.atomic():
                # Store OTP in user profile
                user.profile.otp = otp
                user.profile.save()

                # Send OTP via email
                send_mail(
                    'Password Reset OTP',
                    f'Your OTP for password reset is: {otp}',
                    'saimanideep159@gmail.com',
                    [email],
                    fail_silently=False,
                )
                return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Error during OTP generation: {e}")
            return Response({"error": "Internal server error. OTP generation failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ValidateOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        try:
            # Check if the email exists
            user = User.objects.filter(email=email).first()
            if not user:
                return Response({"error": "User with this email does not exist"}, status=status.HTTP_400_BAD_REQUEST)

            # Verify OTP
            if user.profile.otp != otp:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

            # Mark OTP as verified (for example, set a flag in the user profile)
            with transaction.atomic():
                user.profile.otp_verified = True
                user.profile.save()

            return Response({"message": "OTP verified successfully!"}, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"Error during OTP validation: {e}")
            return Response({"error": "Internal server error. OTP validation failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        new_password = request.data.get('new_password')

        try:
            with transaction.atomic():
                # Check if the email exists
                user = User.objects.filter(email=email).first()
                if not user:
                    return Response({"error": "User with this email does not exist"}, status=status.HTTP_400_BAD_REQUEST)

                # Ensure OTP is verified
                if not user.profile.otp_verified:
                    return Response({"error": "OTP not verified. Please validate the OTP first."}, status=status.HTTP_400_BAD_REQUEST)

                # Reset password
                user.set_password(new_password)
                user.save()

                # Clear the OTP and reset the verification flag
                user.profile.otp = None
                user.profile.otp_verified = False
                user.profile.save()

                return Response({"message": "Password reset successfully!"}, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"Error during password reset: {e}")
            return Response({"error": "Internal server error. Password reset failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')

        try:
            with transaction.atomic():
                # Verify current password
                if not request.user.check_password(current_password):
                    return Response({"error": "Current password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

                # Change password
                request.user.set_password(new_password)
                request.user.save()

                return Response({"message": "Password changed successfully!"}, status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Error during password change: {e}")
            return Response({"error": "Internal server error. Password change failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class HistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Extract JWT token from request headers
            jwt_token = request.headers.get("Authorization").split(" ")[1]  # Bearer <token>
            decoded_token = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_token.get("user_id")

            if not user_id:
                return Response({"error": "User ID not found in token"}, status=status.HTTP_400_BAD_REQUEST)

            # Fetch predictions made by the user
            predictions = PredictionLog.objects.filter(user_id=user_id).order_by('-created_at')

            # Serialize the predictions into a list
            prediction_list = [
                {
                    "age": prediction.age,
                    "speed": prediction.speed,
                    "vehicle_type": prediction.vehicle_type,
                    "fuel_type": prediction.fuel_type,
                    "gaCo2": prediction.ga_co2,
                    "gaTotalEnergyRate": prediction.ga_total_energy_rate,
                    "gaNOx": prediction.ga_nox,
                    "gaPM2.5BrakeWear": prediction.ga_pm25_brake_wear,
                    "gaPM2.5TireWear": prediction.ga_pm25_tire_wear,
                    "timestamp": prediction.created_at
                }
                for prediction in predictions
            ]

            return Response({"predictions": prediction_list}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({"error": "JWT token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"error": "Invalid JWT token"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(f"Error in HistoryView: {e}")
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ResendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')

        # Check if the email exists
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User with this email does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Generate a new OTP
            otp = random.randint(100000, 999999)

            with transaction.atomic():
                # Store OTP in user profile (assuming the profile model has an `otp` field)
                user.profile.otp = otp
                user.profile.save()

                # Resend OTP via email
                send_mail(
                    'Password Reset OTP',
                    f'Your new OTP for password reset is: {otp}',
                    'saimanideep159@gmail.com',
                    [email],
                    fail_silently=False,
                )

                return Response({"message": "New OTP sent to your email"}, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"Error during Resend OTP: {e}")
            return Response({"error": "Internal server error. Unable to resend OTP."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)