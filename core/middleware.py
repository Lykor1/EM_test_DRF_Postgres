from django.http import JsonResponse
from django.conf import settings
from django.urls import resolve
import jwt

from .models import User, AccessRule, BlacklistToken


class AuthMiddleware:
    """
    Посредник для аутентификации.
    Имеет поле с публичными URL-маршрутами, для которых не требуется токен
    и поле с приватными URL-маршрутами (для ресурсов), для которых он необходим.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.public_routes = ('register', 'login')
        self.private_routes = ('products',)
        self.method_permissions = {
            'GET': 'read_permission',
            'POST': 'create_permission',
            'PUT': 'update_permission',
            'DELETE': 'delete_permission',
        }

    def __call__(self, request):
        resolved = resolve(request.path_info)
        if resolved.url_name in self.public_routes:
            return self.get_response(request)
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            if BlacklistToken.objects.filter(token=token).exists():
                return JsonResponse({'error': 'Токен в чёрном списке'}, status=401)
            try:
                payload = jwt.decode(token, settings.SECRET_KEY_JWT, algorithms=[settings.JWT_ALGORITHM])
                user = User.objects.get(id=payload['user_id'], is_active=True)
                request.user = user
                if resolved.url_name == self.private_routes[0]:
                    if not request.user:
                        return JsonResponse({'error': 'Unauthorized'}, status=401)
                rules = AccessRule.objects.filter(role=request.user.role, resource__name='products')
                if not rules.exists():
                    return JsonResponse({'error': 'Forbidden'}, status=403)
                permission_field = self.method_permissions.get(request.method)
                if permission_field and not rules.filter(**{permission_field: True}).exists():
                    return JsonResponse({'error': 'Forbidden'}, status=403)
                # Не очень красиво, нарушает DRY, но я не придумал элегантного решения
                if request.method == 'GET' and not rules.filter(read_all_permission=True).exists():
                    return JsonResponse({'error': 'Forbidden'}, status=403)
            except (jwt.InvalidTokenError, User.DoesNotExist):
                return JsonResponse({'error': 'Unauthorized'}, status=401)
        else:
            return JsonResponse({'error': 'Authorization header required'}, status=401)
        return self.get_response(request)
