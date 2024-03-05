from typing import Any, Annotated

from fastapi import Depends, Response
from fastapi.security import SecurityScopes


from src.config import cfg
from src.crud import CRUDOps
from src.schemas import (UserInDBSchema,
                         ServiceProviderInDBSchema)
from src.schemas.tokens import AccessTokenData, TokenResponse
from src.types import UserType
from src.types.scopes import Scopes

from src import commons
from src.commons.exceptions import (CredentialsException,
                         InvalidScopesSelectionException,
                         InvalidTokenException,
                         NotEnoughPermissionException)


HTTPS_ONLY_COOKIE = cfg.cookies.https_only
COOKIE_DOMAIN = cfg.cookies.domain
REFRESH_TOKEN_EXPIRE_TIME = cfg.same_site.exp_time.refresh_token
SAME_SITE_JWT_SIGNING_ALGORITHM = cfg.same_site.jwt.signing_algorithm
SAME_SITE_JWT_SIGNING_PRIVATE_KEY = cfg.same_site.jwt.keys.private_key
SAME_SITE_JWT_SIGNING_PUBLIC_KEY = cfg.same_site.jwt.keys.public_key


scopes = {
    Scopes.admin.value: "Allow all permissions related to admin of principal user",
    Scopes.worker.value: "Allow all permissions related to worker of principal user",
    Scopes.service_provider.value: "Allow all permissions related to admin of service provider"
}


oauth2_scheme = commons.OAuth2PasswordBearerExtended(tokenUrl="/auth/token", scopes=scopes)


#########################################################
#               Blocking Utility Functions              #
#########################################################


def authenticate_user(org_identifier: str, username: str, password: str) -> UserInDBSchema:
    user = CRUDOps.get_user_by_username(org_identifier=org_identifier, username=username)

    if (user and commons.verify_password(password, user.hashed_password)):
        return user
    else:
        raise CredentialsException


def authenticate_service_provider(username: str, password: str) -> ServiceProviderInDBSchema:
    service_provider = CRUDOps.get_service_provider_by_username(username)

    if (service_provider and commons.verify_password(password, service_provider.hashed_password)):
        return service_provider
    else:
        raise CredentialsException


def decode_jwt_token(token: str) -> dict[str, Any]:
    return commons.decode_jwt_token(
        token=token,
        algorithms=[SAME_SITE_JWT_SIGNING_ALGORITHM],
        public_key=SAME_SITE_JWT_SIGNING_PUBLIC_KEY
    )


def encode_to_jwt_token(data: dict[str, Any]) -> str:
    return commons.encode_to_jwt_token(
        data=data,
        algorithm=SAME_SITE_JWT_SIGNING_ALGORITHM,
        private_key=SAME_SITE_JWT_SIGNING_PRIVATE_KEY
    )


def is_allowed_to_grant_scopes_to_user_type(scopes: list[Scopes], user_type: UserType):
    if (len(scopes) == 1):
        return (
            (Scopes.service_provider in scopes and user_type is UserType.SERVICE_PROVIDER)
            or (Scopes.worker        in scopes and user_type is UserType.WORKER_USER)
        )
    
    elif (len(scopes) == 2 and Scopes.admin in scopes and Scopes.worker in scopes):
        return (user_type is UserType.ADMIN_USER)
    else:
        return False


def process_scopes(scopes: list[Scopes]) -> list[Scopes]:
    """
    checks if combination of scopes in correct or can be correcected
    without removal of any scope for given scopes and return the
    list of corrected scopes
    """
    if (len(scopes) >= len(Scopes.__members__)):
        raise InvalidScopesSelectionException

    if (len(scopes) == 1):
        return [Scopes.admin, Scopes.worker] if (Scopes.admin in scopes) else scopes
    elif (len(scopes) == 2 and Scopes.worker in scopes and Scopes.admin in scopes):
        return scopes
    else:
        raise InvalidScopesSelectionException


def set_tokens_in_cookie(response: Response, token: TokenResponse, cookie_path_for_refresh_token: str = "/", domain: str | None = COOKIE_DOMAIN):
    response.set_cookie(
        key="access_token",
        value=token.access_token,
        expires=token.expires_in,
        domain=domain,
        secure=HTTPS_ONLY_COOKIE,
        httponly=True,
        samesite="strict"
    )
    
    response.set_cookie(
        key="refresh_token",
        value=token.refresh_token,
        expires=REFRESH_TOKEN_EXPIRE_TIME,
        path=cookie_path_for_refresh_token,
        domain=domain,
        secure=HTTPS_ONLY_COOKIE,
        httponly=True,
        samesite="strict"
    )

#########################################################
#             NonBlocking Utility Functions             #
#########################################################


async def get_current_user(security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]):
    """
    here by user stands for all members of UserType Enum
    """
    token_data = AccessTokenData(**decode_jwt_token(token))

    if (token_data.user_type.is_principal_user()):
        org_identifier, user_id = commons.decode_sub_for_principal_user(sub=token_data.sub)
        user = CRUDOps.get_user_by_user_id(org_identifier=org_identifier, user_id=user_id)
    else:
        user = CRUDOps.get_service_provider_by_username(token_data.sub)

    if user is None:
        raise InvalidTokenException

    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise NotEnoughPermissionException(scopes=security_scopes.scopes)


    return user
