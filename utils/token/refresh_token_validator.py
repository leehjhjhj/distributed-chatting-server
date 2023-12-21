from rest_framework_simplejwt.tokens import RefreshToken
from utils.redis_utils import get_redis_connection
from rest_framework_simplejwt.exceptions import TokenError
from utils.exceptions import (
                                NotValidTokenError,
                                NotMatchTokenUserError,
                                AleadyLogoutUserError,
                                RefreshTokenNotMatchError,
                            )
from redis import Redis

class TokenValidator:
    def __init__(self, token: str, user_id: int = None):
        self._refresh_token: str = token
        self._user_id: int = user_id
        self._redis_conn: Redis = get_redis_connection(db_select=3)
       
    @classmethod
    def get_user_id_from_refresh_token(self, refresh_token):
        try:
            token_object = RefreshToken(refresh_token)
            token_user_id: int = token_object.payload.get('user_id')
            return token_user_id
        except TokenError:
            raise NotValidTokenError
        
    def validate_token(self):
        try:
            RefreshToken(self._refresh_token)
        except TokenError:
            raise NotValidTokenError

    def validate_already_logout(self):
        user_id: int = str(self._user_id)
        if not self._redis_conn.exists(user_id):
            raise AleadyLogoutUserError

    def validate_refresh_token_match(self):
        str_user_id: str = str(self._user_id)
        redis_refresh_token = self._redis_conn.get(str_user_id)
        if self._refresh_token != redis_refresh_token:
            raise RefreshTokenNotMatchError