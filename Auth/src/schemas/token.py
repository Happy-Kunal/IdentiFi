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
    sub: str
    user_type: UserType
    iss: str
    scopes: List[Scopes]
    exp: datetime


class AccessTokenData(RefreshTokenData):
    pass