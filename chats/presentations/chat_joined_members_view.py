from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from chats.containers import ChatsContainer
from rest_framework.permissions import IsAuthenticated

class ChatJoinedMembersView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._chat_get_service = ChatsContainer.chat_get_service()

    def get(self, request, chat_id: int):
        response = self._chat_get_service.get_joined_members(chat_id)
        return Response(response, status=status.HTTP_200_OK)