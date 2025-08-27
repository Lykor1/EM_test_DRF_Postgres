from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import BasePermission
from django.conf import settings
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone

from .serializers import UserRegisterSerializer, UserLoginSerializer, AccessRuleSerializer, UserUpdateSerializer
from .models import User, AccessRule, BlacklistToken


class UserRegisterView(APIView):
    """
    Представление для регистрации.
    Реализует только POST запросы.
    """

    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({'message': 'Пользователь успешно создан!'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    """
    Представление для входа.
    Реализует только POST запрос.
    Производит вход по email. Также задаёт время действия токена.
    """

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password'].encode('utf-8')
            try:
                user = User.objects.get(email=email, is_active=True)
                if bcrypt.checkpw(password, user.password.encode('utf-8')):
                    payload = {
                        'user_id': user.id,
                        'exp': datetime.now(timezone.utc) + timedelta(hours=24),
                    }
                    token = jwt.encode(payload, settings.SECRET_KEY_JWT, algorithm=settings.JWT_ALGORITHM)
                    return Response({'token': token}, status=status.HTTP_200_OK)
                return Response({'error': 'Неверный пароль'}, status=status.HTTP_401_UNAUTHORIZED)
            except User.DoesNotExist:
                return Response({'error': 'Пользователь не найден'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class IsAdmin(BasePermission):
    """
    Класс для прав админа.
    Реализовано, конечно, с использованием стандартного функционала DRF,
    но иначе я не придумал.
    """

    def has_permission(self, request, view):
        return request.user and request.user.role.name == 'admin'


class AccessRuleView(APIView):
    """
    Представление для изменения прав доступа к ресурсам для админа.
    Реализует и GET, и POST запросы.
    """
    permission_classes = [IsAdmin]

    def get(self, request):
        rules = AccessRule.objects.all()
        serializer = AccessRuleSerializer(rules, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = AccessRuleSerializer(data=request.data)
        if serializer.is_valid():
            rule = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserUpdateView(APIView):
    """
    Представление для обновления данных пользователя.
    Реализует PATCH запросы.
    Для доступа нужно быть авторизованным.
    """

    def patch(self, request):
        if not request.user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = UserUpdateSerializer(instance=request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Профиль обновлён!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserDeleteView(APIView):
    """
    Представление для мягкого удаления пользователя.
    Реализует DELETE запрос.
    """

    def delete(self, request):
        if not request.user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        request.user.is_active = False
        request.user.save()
        return Response({'message': 'Аккаунт удалён!'}, status=status.HTTP_200_OK)


class UserLogoutView(APIView):
    """
    Представление для выхода.
    Реализует только POST запрос.
    При выходе заносит токен пользователя в чёрный список для защиты.
    """

    def post(self, request):
        if not request.user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        auth_header = request.header.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            BlacklistToken.objects.create(token=token)
            return Response({'message': 'Успешный выход!'}, status=status.HTTP_200_OK)
        return Response({'error': 'Требуется токен!'}, status=status.HTTP_400_BAD_REQUEST)


class ProductView(APIView):
    """
    Mock-представление для тестовых данных.
    """
    def get(self, request):
        return Response([
            {'id': 1, 'name': 'Product 1', 'owner_id': request.user.id},
            {'id': 2, 'name': 'Product 2', 'owner_id': request.user.id}
        ], status=status.HTTP_200_OK)

    def post(self, request):
        return Response({'message': 'Продукт создан!'}, status=status.HTTP_201_CREATED)
