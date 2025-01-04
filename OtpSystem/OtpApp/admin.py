from django.contrib import admin
from .models import CustomUser, OtpToken
from django.contrib.auth.admin import UserAdmin
# Register your models here.

class CustomUserAdmin(UserAdmin):
    # Ajout des champs dans la vue liste de l'administration
    list_display = ('username', 'email', 'is_active', 'last_ip', 'last_seen')
    
    # Ajout des champs dans la vue détaillée de l'utilisateur
    

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2')}
         ),
    )


class OtpTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "otp_code", "otp_expires_at", "otp_attempts")  # Ajout des informations utiles



admin.site.register(OtpToken, OtpTokenAdmin)
admin.site.register(CustomUser, CustomUserAdmin)
    
