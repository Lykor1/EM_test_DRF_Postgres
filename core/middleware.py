from django.http import JsonResponse
from django.conf import settings
from django.urls import resolve
import jwt

from .models import User


class AuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.public_routes = {'register', 'login'}

    def __call__(self, request):
        resolved = resolve(request.path_info)
        if resolved.url_name in self.public_routes:
            return self.get_response(request)
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                payload = jwt.decode(token, settings.SECRET_KEY_JWT, algorithms=[settings.JWT_ALGORITHM])
                user = User.objects.get(id=payload['user_id'], is_active=True)
                request.user = user
            except (jwt.InvalidTokenError, User.DoesNotExist):
                return JsonResponse({'error': 'Unauthorized'}, status=401)
        else:
            return JsonResponse({'error': 'Authorization header required'}, status=401)
        return self.get_response(request)
