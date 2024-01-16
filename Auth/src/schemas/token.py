from typing import List, Union
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel
from pydantic import field_serializer
from pydantic import EmailStr

from src.types.user_types import UserType
from src.types.scopes import Scopes, OIDCScopes

class TokenResponseBase(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str


class TokenResponse(TokenResponseBase):
    scope: str


class OIDCTokenResponse(TokenResponseBase):
    id_token: str


class TokenDataBase(BaseModel):
    sub: str
    user_type: UserType
    iss: str
    exp: datetime


class AccessTokenData(TokenDataBase):
    scopes: List[Scopes]


class RefreshTokenData(AccessTokenData):
    pass


class OIDCCommons(BaseModel):
    aud: UUID
    fid: UUID

    @field_serializer("aud")
    def serialize_aud(self, aud: UUID, _info):
        return str(aud)

    @field_serializer("fid")
    def serialize_fid(self, fid: UUID, _info):
        return str(fid)


class OIDCAccessTokenData(TokenDataBase, OIDCCommons):
    scopes: List[OIDCScopes]


class OIDCRefreshTokenData(OIDCAccessTokenData):
    pass


class OIDCIDTokenData(OIDCCommons):
    """
    required claims as per:
    https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    """
    iss: str
    sub: str
    exp: datetime
    iat: datetime

    email: Union[EmailStr, None] = None
    name: Union[str, None] = None
    preferred_username: Union[str, None] = None

    user_type: UserType = UserType.OIDC_CLIENT
