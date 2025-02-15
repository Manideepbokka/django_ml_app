from rest_framework_simplejwt.authentication import JWTAuthentication

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # First, check for the token in the Authorization header
        header = self.get_header(request)
        if header is None:
            # If no Authorization header, check for token in cookies
            raw_token = request.COOKIES.get('access_token')
        else:
            raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None

        # Validate the token
        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), validated_token
