from django.urls import path
from . import views 

urlpatterns = [
    path("", views.index, name="index"),
    path('home/', views.home, name='home'),
    path("register", views.signup, name="register"),
    path("verify-email/<slug:username>", views.verify_email, name="verify-email"),
    path("resend-otp", views.resend_otp, name="resend-otp"),
    path("login", views.signin, name="signin"),
    path("reset_pass", views.check_email_exists, name="reset_pass"),
    path("otp_resetpass", views.otp_resetpass, name="otp_resetpass"),  
    path("reset-password/<str:username>", views.reset_password, name="reset_password"),
    path("logout/", views.logout_view, name="logout"),
]
