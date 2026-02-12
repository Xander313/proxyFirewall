from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Aplicaciones.accounts'

    def ready(self):
        # Connect signals
        try:
            from . import signals  # noqa: F401
        except Exception:
            # Avoid breaking manage.py commands when DB/migrations aren't ready
            pass

        # Create an admin user with hardcoded credentials if it doesn't exist.
        # This is intentionally simple for demo purposes.
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            username = 'admin'
            password = 'Admin123!'
            email = 'admin@example.com'
            # Use Django ORM to check/create user; guard against DB not ready.
            if not User.objects.filter(username=username).exists():
                User.objects.create_superuser(username=username, email=email, password=password)
        except Exception:
            # OperationalError or other startup-time exceptions are ignored here.
            pass
