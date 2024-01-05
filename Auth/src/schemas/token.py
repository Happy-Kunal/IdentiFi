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
    org_id: UUID
    sub: str
    user_type: UserType
    iss: str
    exp: datetime

    @field_serializer("org_id")
    def serialize_org_id(self, org_id: UUID, _info):
        return str(org_id)


class AccessTokenData(RefreshTokenData):
    scopes: List[Scopes]