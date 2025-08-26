from django.urls import path

from .views import UserRegisterView, UserLoginView, AccessRuleView

urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('rules/', AccessRuleView.as_view(), name='rules'),
]
