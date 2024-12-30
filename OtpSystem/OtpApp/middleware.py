from django.utils.timezone import now

class LogIPAddressMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Ajouter l'adresse IP à chaque requête
        ip = self.get_client_ip(request)
        if request.user.is_authenticated:
            # Enregistrer l'adresse IP et l'heure de la requête pour les utilisateurs connectés
            request.user.last_ip = ip
            request.user.last_seen = now()
            request.user.save()
        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
