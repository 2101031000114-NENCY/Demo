from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.register_view, name='register'),
    path('api/register/', views.api_register_view, name='api_register'),
    path('login/', views.login_view, name='login'),
    path('api/login/', views.api_login_view, name='api_login'),
    path('logout/', views.logout_view, name='logout'),
    path('api/logout/', views.api_logout_view, name='api_logout'),
    path('home/', views.home_view, name='home'),
    path('api/home/', views.api_home_view, name='api_home'),
    path('profile/', views.profile_view, name='profile'),
    path('api/profile/', views.api_profile_view, name='api_profile'),
    path('change_password/', views.change_password_view, name='change_password'),
    path('api/change_password/', views.api_change_password_view, name='api_change_password'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('api/forgot_password/', views.api_forgot_password, name='api_forgot_password'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('api/verify_otp/', views.api_verify_otp, name='api_verify_otp'),
    path('reset_password/', views.reset_password, name='reset_password'),
    path('api/reset_password/', views.api_reset_password, name='api_reset_password'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)