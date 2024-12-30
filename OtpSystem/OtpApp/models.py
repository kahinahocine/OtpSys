from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model
from django.conf import settings
import secrets
# Create your models here.

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)

    # Définir is_active sur False par défaut
    is_active = models.BooleanField(default=False)
    
    # Remplacer le champ username par l'email
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]  # Ne pas inclure 'email' ici.
    failed_attempts = models.IntegerField(default=0)
    last_login_attempt = models.DateTimeField(null=True, blank=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return self.email

    

class OtpToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="otps")
    otp_code = models.CharField(max_length=6, default=secrets.token_hex(3))
    tp_created_at = models.DateTimeField(auto_now_add=True)
    otp_expires_at = models.DateTimeField(blank=True, null=True)
    otp_attempts = models.PositiveIntegerField(default=0) 
    
    
    def __str__(self):
        return self.user.username
    