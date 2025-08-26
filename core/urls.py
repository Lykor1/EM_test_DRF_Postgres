from django.urls import path

from .views import UserRegisterView, UserLoginView, AccessRuleView, UserUpdateView, UserDeleteView

urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/update/', UserUpdateView.as_view(), name='update'),
    path('profile/delete/', UserDeleteView.as_view(), name='delete'),
    path('rules/', AccessRuleView.as_view(), name='rules'),
]
