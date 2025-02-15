from django.apps import AppConfig


class MlApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ml_api'

    def ready(self):
        import ml_api.signals
