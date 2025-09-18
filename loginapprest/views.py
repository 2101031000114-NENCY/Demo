from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django.contrib import messages
from .models import UserProfile, OTP
import logging
import re
import time
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django import forms
from .serializers import (
    UserProfileSerializer, UserSerializer, RegisterSerializer,
    PasswordChangeSerializer, ForgotPasswordSerializer,
    VerifyOTPSerializer, ResetPasswordSerializer
)
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['name', 'phone', 'gender', 'image']

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if phone and not re.match(r'^\+?\d{7,16}$', phone):
            raise forms.ValidationError("Enter a valid phone number (7-16 digits, optional +).")
        if phone and UserProfile.objects.filter(phone=phone).exclude(user=self.instance.user).exists():
            raise forms.ValidationError("Phone number is already registered.")
        return phone

class RegisterForm(forms.Form):
    username = forms.CharField(max_length=150, required=True)
    email = forms.EmailField(required=True)
    phone = forms.CharField(max_length=17, required=True)
    password = forms.CharField(widget=forms.PasswordInput, required=True)
    confirm_password = forms.CharField(widget=forms.PasswordInput, required=True, label="Confirm Password")
    gender = forms.ChoiceField(choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Other')], required=True)

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if len(username) < 3:
            raise forms.ValidationError("Username must be at least 3 characters long.")
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Username is already taken.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email is already registered.")
        return email

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if not re.match(r'^\+?\d{7,16}$', phone):
            raise forms.ValidationError("Enter a valid phone number (7-16 digits, optional +).")
        if UserProfile.objects.filter(phone=phone).exists():
            raise forms.ValidationError("Phone number is already registered.")
        return phone

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")
        if password:
            if len(password) < 8:
                raise forms.ValidationError("Password must be at least 8 characters long.")
            if not re.search(r'[0-9]', password):
                raise forms.ValidationError("Password must contain at least one number.")
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                raise forms.ValidationError("Password must contain at least one special character (e.g., !, @, #).")
            if not re.search(r'[A-Z]', password):
                raise forms.ValidationError("Password must contain at least one uppercase letter.")
            if not re.search(r'[a-z]', password):
                raise forms.ValidationError("Password must contain at least one lowercase letter.")
        return cleaned_data

def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = User.objects.create_user(
                username=form.cleaned_data['username'],
                email=form.cleaned_data['email'],
                password=form.cleaned_data['password']
            )
            UserProfile.objects.create(
                user=user,
                phone=form.cleaned_data['phone'],
                gender=form.cleaned_data['gender']
            )
            messages.success(request, 'Registration successful! You can now log in.')
            return redirect('login')
        else:
            for error in form.non_field_errors():
                messages.error(request, error)
            for field in form:
                for error in field.errors:
                    messages.error(request, f"{field.label}: {error}")
    else:
        form = RegisterForm()
    return render(request, 'loginapprest/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if not username or not password:
            messages.error(request, 'Username and password are required.')
        else:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                if request.POST.get('remember'):
                    request.session.set_expiry(600)
                else:
                    request.session.set_expiry(0)
                if 'application/json' in request.META.get('HTTP_ACCEPT', '') or request.content_type == 'application/json':
                    refresh = RefreshToken.for_user(user)
                    return JsonResponse({
                        'status': 'success',
                        'message': 'Login successful',
                        'access': str(refresh.access_token),
                        'refresh': str(refresh),
                        'user': {
                            'id': user.id,
                            'username': user.username,
                            'email': user.email
                        }
                    })
                messages.success(request, 'Login successful!')
                return redirect('home')
            else:
                messages.error(request, 'Invalid username or password.')
    request.session['access_forgot_password'] = True               
    return render(request, 'loginapprest/login.html')

def home_view(request):
    if not request.user.is_authenticated:
        messages.error(request, 'Please login to access the dashboard.')
        return redirect('login')
    return render(request, 'loginapprest/home.html')

def profile_view(request):    
    if not request.user.is_authenticated:
        messages.error(request, 'Please login to view your profile.')
        return redirect('login')
    try:
        user_profile = request.user.userprofile
    except UserProfile.DoesNotExist:
        user_profile = UserProfile.objects.create(user=request.user)

    if request.method == 'POST' and request.GET.get('edit') == 'true':
        form = UserProfileForm(request.POST, request.FILES, instance=user_profile)
        has_changes = False
        if form.has_changed():
            has_changes = True
        if form.is_valid():
            form.save()
            if has_changes:
                messages.success(request, 'Profile updated successfully!')
            else:
                messages.success(request, 'No updates made!')
            return redirect('profile')
        else:
            for error in form.non_field_errors():
                messages.error(request, error)
            for field in form:
                for error in field.errors:
                    messages.error(request, f"{field.label}: {error}")
    else:
        form = UserProfileForm(instance=user_profile)
    return render(request, 'loginapprest/profile.html', {'form': form, 'user': request.user})

def forgot_password(request):
    if not request.session.get('access_forgot_password'):
        return render(request, 'loginapprest/access_denied.html')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        if not email:
            messages.error(request, 'Email is required.')
        elif not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            messages.error(request, 'Enter a valid email address.')
        elif len(email) > 254:
            messages.error(request, 'Email is too long.')
        else:
            try:
                user = User.objects.get(email=email)
                otp = get_random_string(length=6, allowed_chars='1234567890')
                request.session['otp'] = otp
                request.session['reset_email'] = email
                request.session['otp_timestamp'] = time.time()

                send_mail(
                    'Reset Password OTP',
                    f'Your OTP is: {otp}. It expires in 3 minutes.',
                    'your_sender_email@gmail.com',
                    [email],
                    fail_silently=False,
                )
                messages.success(request, 'OTP sent to your email.')
                return redirect('verify_otp')
            except User.DoesNotExist:
                messages.error(request, 'Email not found.')
    return render(request, 'loginapprest/forgot_password.html', {})

def verify_otp(request):
    if not request.session.get('reset_email'):
        return render(request, 'loginapprest/access_denied.html')
    
    if request.method == 'POST':
        if 'resend_otp' in request.POST:
            email = request.session.get('reset_email')
            if not email:
                messages.error(request, 'Session expired. Please start over.')
                return redirect('forgot_password')
            try:
                user = User.objects.get(email=email)
                otp = get_random_string(length=6, allowed_chars='1234567890')
                request.session['otp'] = otp
                request.session['otp_timestamp'] = time.time()

                send_mail(
                    'Reset Password OTP',
                    f'Your new OTP is: {otp}. It expires in 3 minutes.',
                    'your_sender_email@gmail.com',
                    [email],
                    fail_silently=False,
                )
                messages.success(request, 'New OTP sent to your email.')
                return redirect('verify_otp')
            except User.DoesNotExist:
                messages.error(request, 'Email not found.')
                return redirect('forgot_password')

        otp = request.POST.get('otp')
        if not otp:
            messages.error(request, 'OTP is required.')
        elif len(otp) > 6:
            messages.error(request, 'OTP must be 6 digits.')
        else:
            otp_timestamp = request.session.get('otp_timestamp')
            if otp_timestamp and (time.time() - otp_timestamp) > 180:
                messages.error(request, 'OTP has expired. Please request a new one.')
                return render(request, 'loginapprest/verify_otp.html', {})
            if otp == request.session.get('otp'):
                del request.session['otp']
                del request.session['otp_timestamp']
                return redirect('reset_password')
            else:
                messages.error(request, 'Invalid OTP.')
    return render(request, 'loginapprest/verify_otp.html', {})

class ResetPasswordForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput, required=True, label="New Password")
    confirm_password = forms.CharField(widget=forms.PasswordInput, required=True, label="Confirm Password")

    def clean_new_password(self):
        new_password = self.cleaned_data.get('new_password')
        if len(new_password) < 8:
            raise forms.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[0-9]', new_password):
            raise forms.ValidationError("Password must contain at least one number.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
            raise forms.ValidationError("Password must contain at least one special character (e.g., !, @, #).")
        if not re.search(r'[A-Z]', new_password):
            raise forms.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', new_password):
            raise forms.ValidationError("Password must contain at least one lowercase letter.")
        return new_password

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        if new_password and confirm_password and new_password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned_data

def reset_password(request):
    email = request.session.get('reset_email')
    if not email:
        return render(request, 'loginapprest/access_denied.html')
    
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            user = User.objects.get(email=email)
            user.set_password(form.cleaned_data['new_password'])
            user.save()
            update_session_auth_hash(request, user)
            del request.session['reset_email']
            messages.success(request, 'Password reset successfully.')
            return redirect('login')
        else:
            for error in form.non_field_errors():
                messages.error(request, error)
            for field in form:
                for error in field.errors:
                    messages.error(request, f"{field.label}: {error}")
    else:
        form = ResetPasswordForm()
    return render(request, 'loginapprest/reset_password.html', {'form': form})

class CustomPasswordChangeForm(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput, required=True, label="Current Password")
    new_password1 = forms.CharField(widget=forms.PasswordInput, required=True, label="New Password")
    new_password2 = forms.CharField(widget=forms.PasswordInput, required=True, label="Confirm New Password")

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_old_password(self):
        old_password = self.cleaned_data.get('old_password')
        if not self.user.check_password(old_password):
            raise forms.ValidationError("Current password is incorrect.")
        return old_password

    def clean(self):
        cleaned_data = super().clean()
        old_password = cleaned_data.get('old_password')
        new_password1 = cleaned_data.get('new_password1')
        new_password2 = cleaned_data.get('new_password2')
        if new_password1 and new_password2 and new_password1 != new_password2:
            raise forms.ValidationError("Passwords do not match.")
        if new_password1:
            if len(new_password1) < 8:
                raise forms.ValidationError("Password must be at least 8 characters long.")
            if not re.search(r'[0-9]', new_password1):
                raise forms.ValidationError("Password must contain at least one number.")
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password1):
                raise forms.ValidationError("Password must contain at least one special character (e.g., !, @, #).")
            if not re.search(r'[A-Z]', new_password1):
                raise forms.ValidationError("Password must contain at least one uppercase letter.")
            if not re.search(r'[a-z]', new_password1):
                raise forms.ValidationError("Password must contain at least one lowercase letter.")
            if old_password and new_password1 and old_password == new_password1:
                raise forms.ValidationError("New password cannot be the same as the current password.")
        return cleaned_data

def change_password_view(request):
    if not request.user.is_authenticated:
        messages.error(request, 'Please login to change your password.')
        return redirect('login')

    if request.method == 'POST':
        form = CustomPasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            request.user.set_password(form.cleaned_data['new_password1'])
            request.user.save()
            update_session_auth_hash(request, request.user)
            messages.success(request, 'Password updated successfully!')
            return redirect('home')
        else:
            for error in form.non_field_errors():
                messages.error(request, error)
            for field in form:
                for error in field.errors:
                    messages.error(request, f"{field.label}: {error}")
    else:
        form = CustomPasswordChangeForm(user=request.user)
    return render(request, 'loginapprest/change_password.html', {'form': form, 'user': request.user})

def logout_view(request):
    logout(request)
    messages.success(request, 'Logged out successfully!')
    return redirect('login')    

class Custom404Middleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if response.status_code == 404:
            return render(request, '404.html', status=404)
        return response

    def process_exception(self, request, exception):
        from django.http import Http404
        if isinstance(exception, Http404):
            return render(request, '404.html', status=404)
        return None

@api_view(['POST'])
@permission_classes([AllowAny])
def api_register_view(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user_profile = serializer.save()
        user = user_profile.user
        return Response({
            'status': 'success',
            'message': 'Registration successful',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }, status=status.HTTP_201_CREATED)

    return Response({
        'status': 'error',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def api_login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        refresh = RefreshToken.for_user(user)
        return Response({
            'status': 'success',
            'message': 'Login successful',
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }, status=status.HTTP_200_OK)

    return Response({
        'status': 'error',
        'message': 'Invalid username or password'
    }, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_home_view(request):
    return Response({
        'status': 'success',
        'message': 'Welcome to the dashboard'
    }, status=status.HTTP_200_OK)

@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def api_profile_view(request):
    user = request.user
    try:
        user_profile = user.userprofile
    except UserProfile.DoesNotExist:
        user_profile = UserProfile.objects.create(user=user)

    if request.method == 'GET':
        serializer = UserSerializer(user)
        profile_serializer = UserProfileSerializer(user_profile)
        return Response({
            'status': 'success',
            'user': serializer.data,
            'profile': profile_serializer.data
        }, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        serializer = UserProfileSerializer(user_profile, data=request.data)
        current_data = UserProfileSerializer(user_profile).data
        new_data = request.data
        data_changed = False

        for field in new_data:
            if field in current_data and new_data[field] != current_data[field]:
                data_changed = True
                break

        if serializer.is_valid():
            if data_changed:
                serializer.save()
                return Response({
                    'status': 'success',
                    'message': 'Profile updated successfully',
                    'user': UserSerializer(user).data,
                    'profile': serializer.data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'status': 'success',
                    'message': 'No updates made to profile',
                    'user': UserSerializer(user).data,
                    'profile': serializer.data
                }, status=status.HTTP_200_OK)
        else:
            return Response({
                'status': 'error',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_change_password_view(request):
    serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        request.user.set_password(serializer.validated_data['new_password1'])
        request.user.save()
        update_session_auth_hash(request, request.user)
        return Response({
            'status': 'success',
            'message': 'Password updated successfully'
        }, status=status.HTTP_200_OK)

    return Response({
        'status': 'error',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_logout_view(request):   
    return Response({
        'status': 'success',
        'message': 'Logged out successfully'
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def api_forgot_password(request):
    serializer = ForgotPasswordSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        user = User.objects.get(email=email)
        otp = get_random_string(length=6, allowed_chars='1234567890')
        request.session['otp'] = otp
        request.session['reset_email'] = email
        request.session['otp_timestamp'] = time.time()
        send_mail(
            'Reset Password OTP',
            f'Your OTP is: {otp}. It expires in 3 minutes.',
            'your_sender_email@gmail.com',
            [email],
            fail_silently=False,
        )
        return Response({
            'status': 'success',
            'message': 'OTP sent to your email'
        }, status=status.HTTP_200_OK)

    return Response({
        'status': 'error',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def api_verify_otp(request):
    serializer = VerifyOTPSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']

        if not request.session.get('reset_email') == email:
            return Response({
                'status': 'error',
                'message': 'Invalid session or email'
            }, status=status.HTTP_400_BAD_REQUEST)
        otp_timestamp = request.session.get('otp_timestamp')

        if otp_timestamp and (time.time() - otp_timestamp) > 180:
            return Response({
                'status': 'error',
                'message': 'OTP has expired'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if otp == request.session.get('otp'):
            del request.session['otp']
            del request.session['otp_timestamp']
            return Response({
                'status': 'success',
                'message': 'OTP verified successfully'
            }, status=status.HTTP_200_OK)
        return Response({
            'status': 'error',
            'message': 'Invalid OTP'
        }, status=status.HTTP_400_BAD_REQUEST)

    return Response({
        'status': 'error',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def api_reset_password(request):
    serializer = ResetPasswordSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']

        if not request.session.get('reset_email') == email:
            return Response({
                'status': 'error',
                'message': 'Invalid session or email'
            }, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.get(email=email)
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        del request.session['reset_email']
        return Response({
            'status': 'success',
            'message': 'Password reset successfully'
        }, status=status.HTTP_200_OK)

    return Response({
        'status': 'error',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)