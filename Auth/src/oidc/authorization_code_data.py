from typing import List
from uuid import UUID
from datetime import datetime

from pydantic import HttpUrl
from pydantic import BaseModel
from pydantic import field_serializer

from src.types.scopes import OIDCScopes

class AuthorizationCodeData(BaseModel):
    sub: str
    redirect_uri: HttpUrl
    scopes: List[OIDCScopes]
    client_id: UUID
    exp: datetime

    @field_serializer("client_id")
    def serialize_client_id(self, client_id: UUID, _info):
        return str(client_id)
    
    @field_serializer("redirect_uri")
    def serialize_redirect_uri(self, redirect_uri: HttpUrl, _info):
        return str(redirect_uri)


