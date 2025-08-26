from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone

from .serializers import UserRegisterSerializer, UserLoginSerializer
from .models import User


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
