import re
from django.core.exceptions import ValidationError

def validate_password_complexity(password):
    """
    Vérifie que le mot de passe respecte les critères de complexité :
    - Longueur minimale de 8 caractères
    - Doit contenir au moins une lettre majuscule
    - Doit contenir au moins une lettre minuscule
    - Doit contenir au moins un chiffre
    - Doit contenir au moins un caractère spécial
    """
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r'[0-9]', password):
        raise ValidationError("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError("Password must contain at least one special character.")
