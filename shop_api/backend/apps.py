from django.apps import AppConfig
from django.core.signals import request_finished


class BackendConfig(AppConfig):
    name = 'backend'

    def ready(self):
        import backend.signals
