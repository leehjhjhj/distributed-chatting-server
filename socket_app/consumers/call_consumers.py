from channels.generic.websocket import JsonWebsocketConsumer
from asgiref.sync import async_to_sync
from chats.domains import Chat
from datetime import datetime
from decouple import config
from utils.date import current_time
from utils.redis_utils import get_redis_connection
import boto3
import logging

class ChatConsumer(JsonWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.group_name = ""
        self.dynamodb = boto3.resource(
            'dynamodb', region_name='ap-northeast-2',
            aws_access_key_id=config('AWS_ACCCESS_KEY'),
            aws_secret_access_key=config('AWS_SECRET_ACCESS_KEY')
        )
        self.table = self.dynamodb.Table('clclcafe')
        self.redis_conn = get_redis_connection(db_select=1)

    def receive_json(self, content, **kwargs):
        _type = content["type"]
        _message = content["message"]
        _user_id = content["userId"]
        _user_nickname = content["userNickname"]
        _chat_id = self.chat_id
        _now = datetime.now().isoformat()

        if _type == "chat.message":
            self.table.put_item(
            Item={
                    'message_id': f'{_chat_id}-{_now}',
                    'chat_id': str(_chat_id),
                    'user_id': str(_user_id),
                    'user_nickname': _user_nickname,
                    'message': _message,
                    'timestamp': _now,
                    'chat_time': current_time()
                }
            )
            async_to_sync(self.channel_layer.group_send)(
                self.group_name,
                {
                    "type": "chat.message",
                    "message": _message,
                    "userId": _user_id,
                    "userNickname": _user_nickname
                }
            )
        else:
            logging.ERROR("오류:",_type)

    def connect(self):
        self.chat_id = self.scope["url_route"]["kwargs"]["chat_id"]
        self.group_name = Chat.make_chat_group_name(self.chat_id)

        user = self.scope["user"]
        self.redis_conn.sadd(self.chat_id, user.nickname)
        async_to_sync(self.channel_layer.group_send)(
                        self.group_name,
                        {
                            "type": "chat.user.join",
                            "userId": user.id,
                            "userNickname": user.nickname,
                        }
                    )
        async_to_sync(self.channel_layer.group_add)(
            self.group_name,
            self.channel_name,
        )
        self.accept()

    def disconnect(self, code):
        user = self.scope["user"]
        self.redis_conn.srem(self.chat_id, user.nickname)
        async_to_sync(self.channel_layer.group_send)(
                        self.group_name,
                        {
                            "type": "chat.user.leave",
                            "userId": user.id,
                            "userNickname": user.nickname,
                        }
                    )
        if self.group_name:
            async_to_sync(self.channel_layer.group_discard)(
                self.group_name,
                self.channel_name,
            )

    def chat_message(self, message_dict):
        message = message_dict["message"]
        user_id = message_dict["userId"]
        user_nickname = message_dict["userNickname"]

        self.send_json({
            "type": "chat.message",
            "message": message,
            "userId": user_id,
            "userNickname": user_nickname,
            "chatTime": current_time()
        })

    def chat_user_join(self, message_dict):
        self.send_json({
            "type": "chat.user.join",
            "userId": message_dict['userId'],
            "userNickname": message_dict['userNickname'],
        })

    def chat_user_leave(self, message_dict):
        self.send_json({
            "type": "chat.user.leave",
            "userId": message_dict['userId'],
            "userNickname": message_dict['userNickname'],
        })