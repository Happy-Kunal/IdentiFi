from typing import List
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel
from pydantic import field_serializer

from src.types.user_types import UserType
from src.types.scopes import Scopes

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
    scope: str


class RefreshTokenData(BaseModel):
    client_id: UUID
    sub: str
    user_type: UserType
    iss: str
    scopes: List[Scopes]
    exp: datetime

    @field_serializer("client_id")
    def serialize_client_id(self, client_id: UUID, _info):
        return str(client_id)


class AccessTokenData(RefreshTokenData):
    pass