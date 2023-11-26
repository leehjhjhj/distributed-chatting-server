
import os
from channels.routing import URLRouter, ProtocolTypeRouter
from django.core.asgi import get_asgi_application
from socket_app.routings import chat_routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'server.local.settings')

django_asgi_app = get_asgi_application()
from django_channels_jwt_auth_middleware.auth import JWTAuthMiddlewareStack
application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": JWTAuthMiddlewareStack(
        URLRouter(
            chat_routing.websocket_urlpatterns
        )
    )
})