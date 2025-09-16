from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, unique=True)
    phone = models.CharField(max_length=16, blank=True, null=True, unique=True)
    gender = models.CharField(max_length=10, choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Other')], blank=True, null=True)
    image = models.ImageField(upload_to='profile_images/', null=True, blank=True, default='profile_images/user.png')
    name = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return self.user.username

class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)