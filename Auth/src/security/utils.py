from typing import Any, Annotated
from uuid import UUID

from fastapi import Depends, Response
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import ValidationError

from src.config import cfg
from src.crud import CRUDOps
from src.schemas import (PrincipalUserInDBSchema, ProcessedScopes,
                         ServiceProviderInDBSchema)
from src.schemas.tokens import AccessTokenData, TokenResponse
from src.types import PrincipalUserTypes, UserType
from src.types.scopes import Scopes

from .exceptions import (credentials_exception,
                         invalid_scopes_selection_exception,
                         invalid_token_exception,
                         not_enough_permission_exception)


HTTPS_ONLY_COOKIE = cfg.cookies.https_only
REFRESH_TOKEN_EXPIRE_TIME = cfg.same_site.exp_time.refresh_token
SAME_SITE_JWT_SIGNING_ALGORITHM = cfg.same_site.jwt.signing_algorithm
SAME_SITE_JWT_SIGNING_PRIVATE_KEY = cfg.same_site.jwt.keys.private_key
SAME_SITE_JWT_SIGNING_PUBLIC_KEY = cfg.same_site.jwt.keys.public_key


scopes = {
    Scopes.admin: "Allow all permissions related to admin of principal user",
    Scopes.worker: "Allow all permissions related to worker of principal user",
    Scopes.service_provider: "Allow all permissions related to admin of service provider"
}


password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", scopes=scopes)


#########################################################
#               Blocking Utility Functions              #
#########################################################


def authenticate_user(client_id: UUID, username: str, password: str, user_type: UserType) -> PrincipalUserInDBSchema | ServiceProviderInDBSchema:
    if (user_type == UserType.PRINCIPAL_USER):
        user = CRUDOps.get_prinicipal_user_by_username(client_id, username)
    else:
        user = CRUDOps.get_service_provider_by_username(client_id, username)

    if (user and verify_password(password, user.hashed_password)):
        return user
    else:
        raise credentials_exception
    

def decode_jwt_token(token: str, algorithms: list[str] = [SAME_SITE_JWT_SIGNING_ALGORITHM], public_key: str = SAME_SITE_JWT_SIGNING_PUBLIC_KEY) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, public_key, algorithms=algorithms)
        sub: str = payload.get("sub")
        if sub is None:
            raise invalid_token_exception
        return payload
    except (JWTError, ValidationError):
        raise invalid_token_exception


def encode_to_jwt_token(data: dict[str, Any], algorithm: str = SAME_SITE_JWT_SIGNING_ALGORITHM, private_key: str = SAME_SITE_JWT_SIGNING_PRIVATE_KEY) -> str:
    encoded_jwt = jwt.encode(data.copy(), private_key, algorithm=algorithm)
    return encoded_jwt


def get_password_hash(password: str) -> str:
    return password_context.hash(password)


def is_allowed_to_grant_scopes_to_user(scopes: list[Scopes], user: PrincipalUserInDBSchema | ServiceProviderInDBSchema):
    if (len(scopes) == 1):
        return (
            (Scopes.service_provider in scopes and user.user_type == UserType.SERVICE_PROVIDER)
            or (Scopes.worker        in scopes and user.user_type == UserType.PRINCIPAL_USER)
        )
            
    elif (len(scopes) == 2 and Scopes.admin in scopes and Scopes.worker in scopes):
        return (user.user_type == UserType.PRINCIPAL_USER and user.user_type == PrincipalUserTypes.PRINCIPAL_USER_ADMIN)
    else:
        return False


def process_scopes(scopes: list[Scopes]) -> ProcessedScopes:
    if (len(scopes) >= len(Scopes.__members__)):
        raise invalid_scopes_selection_exception
    
    valid_scopes = Scopes.__members__.values()
    for scope in scopes:
        if (scope not in valid_scopes):
            raise invalid_scopes_selection_exception

    if (len(scopes) == 1):
        if (Scopes.service_provider in scopes):
            return ProcessedScopes(user_type=UserType.SERVICE_PROVIDER, scopes=[Scopes.service_provider])
        elif (Scopes.worker in scopes):
            return ProcessedScopes(user_type=UserType.PRINCIPAL_USER, scopes=[Scopes.worker])
        else:
            raise invalid_scopes_selection_exception

    elif (len(scopes) == 2 and Scopes.worker in scopes and Scopes.admin in scopes):
        return ProcessedScopes(user_type=UserType.PRINCIPAL_USER, scopes=[Scopes.worker, Scopes.admin])
    else:
        raise invalid_scopes_selection_exception


def set_tokens_in_cookie(response: Response, token: TokenResponse, cookie_path_for_refresh_token: str = "/"):
    response.set_cookie(
        key="access_token",
        value=token.access_token,
        expires=token.expires_in,
        secure=HTTPS_ONLY_COOKIE,
        httponly=True,
        samesite="strict"
    )
    
    response.set_cookie(
        key="refresh_token",
        value=token.refresh_token,
        expires=REFRESH_TOKEN_EXPIRE_TIME,
        path=cookie_path_for_refresh_token,
        secure=HTTPS_ONLY_COOKIE,
        httponly=True,
        samesite="strict"
    )


def verify_password(plain_password: str, hashed_password: str):
    return password_context.verify(plain_password, hashed_password)




#########################################################
#             NonBlocking Utility Functions             #
#########################################################


async def get_current_user(security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]):
    token_data = AccessTokenData(**decode_jwt_token(token))

    if (token_data.user_type == UserType.PRINCIPAL_USER):
        user = CRUDOps.get_prinicipal_user_by_username(token_data.client_id, token_data.sub)
    else:
        user = CRUDOps.get_service_provider_by_username(token_data.client_id, token_data.sub)

    if user is None:
        raise invalid_token_exception

    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise not_enough_permission_exception(scopes=security_scopes.scopes)


    return user
