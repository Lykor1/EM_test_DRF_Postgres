from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import BasePermission
from django.conf import settings
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone

from .serializers import UserRegisterSerializer, UserLoginSerializer, AccessRuleSerializer, UserUpdateSerializer
from .models import User, AccessRule


class UserRegisterView(APIView):
    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({'message': 'Пользователь успешно создан!'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
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
    def has_permission(self, request, view):
        return request.user and request.user.role.name == 'admin'


class AccessRuleView(APIView):
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
    def patch(self, request):
        if not request.user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = UserUpdateSerializer(instance=request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Профиль обновлён!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserDeleteView(APIView):
    def delete(self, request):
        if not request.user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        request.user.is_active = False
        request.user.save()
        return Response({'message': 'Аккаунт удалён!'}, status=status.HTTP_200_OK)
