from arrow import now
from django.shortcuts import render, redirect
from requests import Session
from OtpSystem import settings
from .forms import RegisterForm
from .models import OtpToken
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login, logout
from .models import CustomUser, OtpToken
import os
from django.core.exceptions import ValidationError
from .utils import validate_password_complexity 
from datetime import timedelta
from django_ratelimit.decorators import ratelimit

# Create your views here.

def index(request):
    return render(request, "index.html")

def home(request):
    context = {"user": request.user}  # Ajouter l'utilisateur connecté au contexte
    return render(request, "home.html", context)




def signup(request):
    form = RegisterForm()
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            # Créer un utilisateur désactivé
            user = form.save(commit=False)
            user.is_active = False  # Désactiver l'utilisateur
            user.save()

            # Générer un OTP pour cet utilisateur
            otp = OtpToken.objects.create(
                user=user,
                otp_expires_at=timezone.now() + timezone.timedelta(minutes=5)
            )

            # Envoyer un email de vérification
            subject = "Email Verification"
            message = f"""
            Hi {user.username}, here is your OTP: {otp.otp_code}.
            It expires in 5 minutes. Use the URL below to verify your account:
            http://127.0.0.1:8000/verify-email/{user.username}
            """
            sender = os.getenv("EMAIL_HOST_USER")
            receiver = [user.email]

            send_mail(subject, message, sender, receiver, fail_silently=False)
            return redirect("verify-email", username=user.username)

    context = {"form": form}
    return render(request, "signup.html", context)





def verify_email(request, username):
    try:
        user = get_user_model().objects.get(username=username)
    except get_user_model().DoesNotExist:
        messages.error(request, "User does not exist.")
        return redirect("signup")

    user_otp = OtpToken.objects.filter(user=user).last()

    if not user_otp:
        messages.error(request, "No OTP found. Please request a new one.")
        return redirect("resend-otp")

    # Vérification du nombre de tentatives avec MAX_OTP_TRY depuis settings
    if user_otp.otp_attempts >= settings.MAX_OTP_TRY:
        messages.error(request, "Maximum OTP attempts reached. Please request a new OTP.")
        user_otp.delete()  # Supprimer l'OTP après dépassement des tentatives.
        return redirect("resend-otp")

    if request.method == 'POST':
        entered_otp = request.POST.get('otp_code')

        if entered_otp == user_otp.otp_code:
            if user_otp.otp_expires_at > timezone.now():
                user.is_active = True
                user.save()
                user_otp.delete()
                messages.success(request, "Account activated successfully! You can now log in.")
                return redirect("signin")
            else:
                messages.warning(request, "The OTP has expired. Please request a new one.")
                return redirect("resend-otp")
        else:
            user_otp.otp_attempts += 1
            user_otp.save()
            attempts_left = settings.MAX_OTP_TRY - user_otp.otp_attempts
            messages.error(request, f"Invalid OTP. You have {attempts_left} attempts left.")
            return redirect("verify-email", username=username)

    context = {"username": username}
    return render(request, "verify_token.html", context)





def resend_otp(request):
    if request.method == 'POST':
        user_email = request.POST["otp_email"]
        
        if get_user_model().objects.filter(email=user_email).exists():
            user = get_user_model().objects.get(email=user_email)
            otp = OtpToken.objects.create(user=user, otp_expires_at=timezone.now() + timezone.timedelta(minutes=5))
            
            # Email variables
            subject = "Email Verification"
            message = f"""
                                Hi {user.username}, here is your OTP {otp.otp_code} 
                                it expires in 5 minutes. Use the URL below to redirect back to the website:
                                http://127.0.0.1:8000/verify-email/{user.username}
                                """
            sender = os.getenv("EMAIL_HOST_USER")
            receiver = [user.email]
        
            # Envoi de l'email
            send_mail(
                    subject,
                    message,
                    sender,
                    receiver,
                    fail_silently=False,
                )
            
            messages.success(request, "A new OTP has been sent to your email address.")
            return redirect("verify-email", username=user.username)

        else:
            messages.warning(request, "This email doesn't exist in the database.")
            return redirect("resend-otp")  # Redirige vers la page pour renvoyer un OTP
        
    context = {}
    return render(request, "resend_otp.html", context)


from django.utils.timezone import now
from datetime import timedelta

def signin(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Vérifier si l'email est saisi
        if not email:
            messages.error(request, "Please enter your email address.")
            return render(request, "login.html")

        # Vérifier si le mot de passe est saisi
        if not password:
            messages.error(request, "Please enter your password.")
            return render(request, "login.html")

        try:
            # Rechercher l'utilisateur par email
            user = get_user_model().objects.get(email=email)

            # Vérifier si l'utilisateur est inactif
            if not user.is_active:
                user.delete()
                messages.error(request, "Your account has not been activated and has been deleted.")
                return redirect("register")

            # Vérifier si l'utilisateur est verrouillé temporairement
            lock_duration = timedelta(minutes=10)
            if user.last_login_attempt and now() < user.last_login_attempt + lock_duration:
                messages.error(request, "Your account is temporarily locked. Please try again later.")
                return render(request, "login.html")

            # Authentification
            user_authenticated = authenticate(request, username=email, password=password)
            if user_authenticated:
                user.failed_attempts = 0
                user.last_login_attempt = None
                user.save()
                login(request, user)
                messages.success(request, "Welcome back!")
                return redirect("home")
            else:
                user.failed_attempts += 1
                user.last_login_attempt = now()
                user.save()

                # Bloquer le compte si le nombre maximal de tentatives est atteint
                if user.failed_attempts >= settings.MAX_LOGIN_ATTEMPTS:
                    user.is_active = False
                    user.save()
                    messages.error(request, "Your account has been locked due to multiple failed login attempts.")
                else:
                    attempts_left = settings.MAX_LOGIN_ATTEMPTS - user.failed_attempts
                    messages.error(request, f"Invalid credentials. You have {attempts_left} attempts left.")
        except get_user_model().DoesNotExist:
            messages.error(request, "Invalid credentials. Please try again.")

    return render(request, "login.html")



def check_email_exists(request):
    if request.method == "POST":
        email = request.POST.get("email")  # Capture the email from the request
        if email:
            user_exists = CustomUser.objects.filter(email=email).exists()
            if user_exists:
                # Generate OTP and associate it with the user
                user = CustomUser.objects.get(email=email)
                otp = OtpToken.objects.create(
                    user=user,
                    otp_expires_at=timezone.now() + timezone.timedelta(minutes=5)
                )

                # Store user ID in the session
                request.session["user_id"] = user.id

                # Email variables
                subject = "Email Verification - OTP"
                message = f"""
                Hi {user.username}, here is your OTP {otp.otp_code} 
                it expires in 5 minutes. Use the URL below to reset your password:
                http://127.0.0.1:8000/otp_resetpass
                """
                sender = os.getenv("EMAIL_HOST_USER")
                receiver = [user.email]

                # Send the OTP to the user's email
                send_mail(
                    subject,
                    message,
                    sender,
                    receiver,
                    fail_silently=False,
                )

                messages.success(request, "An OTP has been sent to your email for password reset.")
                return redirect("otp_resetpass")  # Redirect to the OTP reset page
            else:
                # Show error message if user does not exist
                messages.warning(request, "This email does not exist in the database.")
                return redirect("reset_pass")  # Redirect to the reset page again
        
    return render(request, "reset_pass.html")



def otp_resetpass(request):
    if request.method == "POST":
        # Récupérer l'utilisateur stocké dans la session
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Aucune session utilisateur active. Veuillez recommencer le processus.")
            return redirect("reset_pass")

        try:
            # Récupérer l'utilisateur correspondant à l'ID
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            messages.error(request, "invalid user.")
            return redirect("reset_pass")

        # Récupérer le dernier OTP pour cet utilisateur
        user_otp = OtpToken.objects.filter(user=user).last()

        if not user_otp:
            messages.error(request, "Aucun OTP trouvé. Veuillez en demander un nouveau.")
            return redirect("resend-otp")

        # Vérifier le nombre de tentatives
        attempts_left = settings.MAX_OTP_TRY - user_otp.otp_attempts  # Calculer les tentatives restantes
        if attempts_left <= 0:
            messages.error(request, "Maximum OTP attempts reached. Please request a new OTP.")
            user_otp.delete()  # Supprimer l'OTP après dépassement des tentatives
            return redirect("reset_pass")

        # Vérification de l'OTP si soumis via un second formulaire
        if "otp_code" in request.POST:
            entered_otp = request.POST.get("otp_code")

            if entered_otp == user_otp.otp_code:
                if user_otp.otp_expires_at and user_otp.otp_expires_at > timezone.now():
                    user_otp.delete()  # Supprimer l'OTP après une vérification réussie
                    messages.success(request, "Reset your password !")
                    return redirect("reset_password", username=user.username)
                else:
                    messages.warning(request, "The otp code has expired.")
                    return redirect("resend-otp")
            else:
                user_otp.otp_attempts += 1
                user_otp.save()
                attempts_left -= 1  # Mettre à jour les tentatives restantes après l'échec
                if attempts_left > 0:
                    messages.error(request, f"Invalid Otp.")
                else:
                    messages.error(request, "Nombre maximum de tentatives atteint. Veuillez demander un nouveau code OTP.")
                    user_otp.delete()
                    return redirect("reset_pass")

                return redirect("otp_resetpass")

    return render(request, "otp_resetpass.html")




def reset_password(request, username):
    try:
        user = get_user_model().objects.get(username=username)
    except get_user_model().DoesNotExist:
        messages.error(request, "User does not exist.")
        return redirect("signin")

    if request.method == "POST":
        new_password = request.POST.get("new_password")
        new_password_confirm = request.POST.get("new_password_confirm")

        # Vérification que les mots de passe correspondent
        if new_password != new_password_confirm:
            messages.error(request, "Passwords do not match. Please try again.")
            return redirect("reset_password", username=username)

        # Validation de la complexité du mot de passe
        try:
            validate_password_complexity(new_password)
        except ValidationError as e:
            messages.error(request, e.message)
            return redirect("reset_password", username=username)

        # Mise à jour du mot de passe
        user.set_password(new_password)
        user.save()
        messages.success(request, "Your password has been successfully reset.")
        return redirect("signin")

    # Affichage du formulaire de réinitialisation du mot de passe
    return render(request, "reset_password.html")



def logout_view(request):
    logout(request)  # Déconnecte l'utilisateur
    return redirect("index")  # Redirige vers la page d'accueil

