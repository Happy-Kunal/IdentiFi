from uuid import UUID
from datetime import datetime

from pydantic import BaseModel, Field
from pydantic import field_serializer
from pydantic import EmailStr, HttpUrl

from src.types import UserType
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
    iss: HttpUrl
    exp: datetime


    @field_serializer("iss")
    def serialize_iss(self, iss, _info):
        return str(iss)


class AccessTokenData(TokenDataBase):
    scopes: list[Scopes]


class RefreshTokenData(AccessTokenData):
    pass


class OIDCCommons(BaseModel):
    aud: UUID
    fid: str = Field(alias="org_identifier", min_length=6, max_length=255)

    @field_serializer("aud")
    def serialize_aud(self, aud: UUID, _info):
        return str(aud)


class OIDCAccessTokenData(OIDCCommons):
    sub: str
    iss: HttpUrl
    exp: datetime
    
    scopes: list[OIDCScopes]
    
    
    @field_serializer("iss")
    def serialize_iss(self, iss, _info):
        return str(iss)



class OIDCRefreshTokenData(OIDCAccessTokenData):
    pass


class OIDCIDTokenData(OIDCCommons):
    """
    required claims as per:
    https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    """
    iss: HttpUrl
    sub: str
    exp: datetime
    iat: datetime

    email: EmailStr | None = None
    name: str | None = None
    preferred_username: str | None = None

    #user_type: UserType = UserType.OIDC_CLIENT


    @field_serializer("iss")
    def serialize_iss(self, iss, _info):
        return str(iss)
