import logging
import urllib.parse
from datetime import datetime, timedelta, timezone
from secrets import compare_digest
from typing import Any, cast, Annotated
from uuid import UUID

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException, status
from fastapi import Request, Response
from fastapi.responses import RedirectResponse
from jose import jwe
from jose.exceptions import JWEError
from pydantic import HttpUrl


from src.config import cfg
from src.crud import CRUDOps
from src.schemas import (AccessTokenData, AuthorizationCodeData,
                         OIDCAccessTokenData, OIDCIDTokenData,
                         OIDCRefreshTokenData, OIDCTokenResponse,
                         UserInDBSchema)

from src.security import decode_jwt_token as decode_jwt_token_same_site
from src import commons
from src.security import oauth2_scheme as user_jwt_access_token_getter_async
from src.types.scopes import OIDCScopes

from .authorization_code_request_params import (
    OAuth2AuthorizationCodeRequestForm, OAuth2AuthorizationCodeRequestQuery)
from .authorization_code_token_request_params import AuthorizationCodeTokenRequestParams


ACCESS_TOKEN_EXPIRE_TIME       = cfg.oidc.exp_time.access_token
AUTHORIZATION_CODE_EXPIRE_TIME = cfg.oidc.exp_time.authcode
ID_TOKEN_EXPIRE_TIME           = cfg.oidc.exp_time.id_token
ISSUER                         = cfg.issuer
JWE_ENCRYPT_ALGORITHM          = cfg.oidc.jwe.algorithms.encryption
JWE_KEY_MANAGEMENT_ALGORITHM   = cfg.oidc.jwe.algorithms.key_management
JWE_SECRET_KEY                 = cfg.oidc.jwe.secret_key
LOGIN_ENDPOINT                 = cfg.login_endpoint
OIDC_JWT_SIGNING_ALGORITHM     = cfg.oidc.jwt.signing_algorithm
OIDC_JWT_SIGNING_PRIVATE_KEY   = cfg.oidc.jwt.keys.private_key
OIDC_JWT_SIGNING_PUBLIC_KEY    = cfg.oidc.jwt.keys.public_key
REFRESH_TOKEN_EXPIRE_TIME      = cfg.oidc.exp_time.refresh_token



logger = logging.getLogger(__name__)


scopes = {
    OIDCScopes.openid: "to obtain id token",
    OIDCScopes.profile: "allow access to user's username, preferred_name, user_id",
    OIDCScopes.email: "allow access to user's email",
    OIDCScopes.service_provider_config: "allow access to user's service-provider-config"
                    " for client whom token is issued set by admin of principal-user (if any)"
}


invalid_client_id_exception = HTTPException(
    status_code=status.HTTP_406_NOT_ACCEPTABLE,
    detail="invalid client_id: no such client exists with given client_id"
)


router = APIRouter(prefix="/oauth2")


def encode_to_jwt_token(data: dict[str, Any]) -> str:
    return commons.encode_to_jwt_token(
        data=data,
        algorithm=OIDC_JWT_SIGNING_ALGORITHM,
        private_key=OIDC_JWT_SIGNING_PRIVATE_KEY
    )


def decode_jwt_token(token: str) -> dict[str, Any]:
    return commons.decode_jwt_token(
        token=token,
        algorithms=[OIDC_JWT_SIGNING_ALGORITHM],
        public_key=OIDC_JWT_SIGNING_PUBLIC_KEY
    )


def encrypt_string(data: str) -> str:
    return jwe.encrypt(
        data,
        key=JWE_SECRET_KEY,
        encryption=JWE_ENCRYPT_ALGORITHM,
        algorithm=JWE_KEY_MANAGEMENT_ALGORITHM
    ).decode("utf-8")

def decrypt_string(data: str):
    try:
        return jwe.decrypt(data, key=JWE_SECRET_KEY)
    except JWEError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid authorization_code",
        )


async def get_logged_in_user(access_token: str) -> UserInDBSchema | None:
    token_data = AccessTokenData(**decode_jwt_token_same_site(access_token))
    if (token_data.user_type.is_principal_user()):
        org_identifier, user_id = commons.decode_sub_for_principal_user(sub=token_data.sub)
        user = CRUDOps.get_user_by_user_id(org_identifier=org_identifier, user_id=user_id)
        return user
    else:
        return None
    



def display_login_screen(redirect_uri: HttpUrl):
    quoted_redirect_uri = urllib.parse.quote(redirect_uri)
    return RedirectResponse(
        url=f"{LOGIN_ENDPOINT}?redirect_uri={quoted_redirect_uri}",
        status_code=status.HTTP_302_FOUND
    )


async def is_valid_client_async(client_id: UUID, client_secret: str | None = None):
    client = CRUDOps.get_service_provider_by_client_id(client_id)
    if (client):
        return client_secret is None or compare_digest(client.client_secret, client_secret)
    
    return False


async def is_consent_form_required(user: UserInDBSchema, client_id: UUID, scopes: list[OIDCScopes]):
    granted_scopes: set[OIDCScopes] = CRUDOps.get_scopes_granted_by_user_to_client(
                                            org_identifier=user.org_identifier,
                                            user_id=user.user_id,
                                            client_id=client_id
                                        )
    
    for scope in scopes:
        if (scope not in granted_scopes):
            return True
    
    return False


async def send_consent_form(redirect_uri: HttpUrl):
    # TODO: add consent functionality
    return NotImplemented


async def generate_authorization_code(
    user: UserInDBSchema,
    client_id: UUID,
    redirect_uri: HttpUrl,
    scopes: list[OIDCScopes]
) -> str:
    authorization_code_data = AuthorizationCodeData(
        sub=commons.encode_sub_for_principal_user(org_identifier=user.org_identifier, user_id=user.user_id),
        redirect_uri=redirect_uri,
        scopes=scopes,
        client_id=client_id,
        exp=datetime.now(timezone.utc) + timedelta(seconds=AUTHORIZATION_CODE_EXPIRE_TIME)
    )

    authorization_code = encrypt_string(
        encode_to_jwt_token(
            authorization_code_data.model_dump()
        )
    )

    return authorization_code


async def create_tokens_from_authcode_data(authcode_data: AuthorizationCodeData) -> OIDCTokenResponse:
    common = {
        "aud": authcode_data.client_id, # client_id of client [service-provider]
        "iss": ISSUER,
        "sub": authcode_data.sub,
        
        "org_identifier": commons.decode_sub_for_principal_user(sub=authcode_data.sub)[0],
        "scopes": authcode_data.scopes,
    }
    
    access_token = OIDCAccessTokenData(
        **common,
        exp=datetime.now(timezone.utc) + timedelta(seconds=ACCESS_TOKEN_EXPIRE_TIME),
    )

    refresh_token = OIDCRefreshTokenData(
        **common,
        exp=datetime.now(timezone.utc) + timedelta(seconds=REFRESH_TOKEN_EXPIRE_TIME),
    )

    id_token = OIDCIDTokenData(
        **common,
        iat=datetime.now(timezone.utc),
        exp=datetime.now(timezone.utc) + timedelta(seconds=ID_TOKEN_EXPIRE_TIME)
    )

    if (len(authcode_data.scopes) > 1):
        org_identifier, user_id = commons.decode_sub_for_principal_user(authcode_data.sub)
        user = CRUDOps.get_user_by_user_id(org_identifier=org_identifier, user_id=user_id)

        if (OIDCScopes.profile in authcode_data.scopes):
            id_token.name = user.name
            id_token.preferred_username = user.username
        
        if (OIDCScopes.email in authcode_data.scopes):
            id_token.email = user.email

    return OIDCTokenResponse(
        token_type="Bearer",
        access_token=encode_to_jwt_token(access_token.model_dump()),
        refresh_token=encode_to_jwt_token(refresh_token.model_dump()),
        id_token=encode_to_jwt_token(id_token.model_dump(exclude_none=True)),
        expires_in=ACCESS_TOKEN_EXPIRE_TIME,
    )




@router.get("/authorize")
async def authorize(
    request: Request,
    query_data: Annotated[OAuth2AuthorizationCodeRequestQuery, Depends()],
):
    access_token = await user_jwt_access_token_getter_async(request=request)
    
    if (not access_token):
        return display_login_screen(redirect_uri=request.url._url)
    
    user = await get_logged_in_user(access_token=access_token)
    valid_requested_scopes = query_data.scopes.intersection(OIDCScopes)


    if (not user):
        return display_login_screen(redirect_uri=request.url._url)
    elif (not await is_valid_client_async(client_id=query_data.client_id)):
        raise invalid_client_id_exception
    elif (await is_consent_form_required(user=user, client_id=query_data.client_id, scopes=valid_requested_scopes)):
        return await send_consent_form(redirect_uri=request.url._url)
    else:
        auth_code = await generate_authorization_code(
            user=user,
            client_id=query_data.client_id,
            redirect_uri=query_data.redirect_uri,
            scopes=valid_requested_scopes
        )

        return RedirectResponse(
            url=f"{query_data.redirect_uri}?code={auth_code}&state={query_data.state}",
            status_code=status.HTTP_302_FOUND
        )


@router.post("/authorize")
async def authorize_by_post(
    request: Request,
    form_data: Annotated[OAuth2AuthorizationCodeRequestForm, Depends()],
):
    return await authorize(
        request=request,
        query_data=cast(OAuth2AuthorizationCodeRequestQuery, form_data),
    )


@router.post("/token", response_model=OIDCTokenResponse)
async def token_from_authorization_code(
    response: Response,
    params: AuthorizationCodeTokenRequestParams
):
    authcode_data = AuthorizationCodeData(
        **decode_jwt_token(
            token=decrypt_string(params.code)
        )
    )

    if (not await is_valid_client_async(client_id=params.client_id, client_secret=params.client_secret)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid client credentials"
        )
    elif (params.client_id != authcode_data.client_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="authorization code does not belong to this client"
        )
    elif (params.redirect_uri != authcode_data.redirect_uri):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="redirect_uri in request does not match with redirect_uri"
            "used in authorization code generation"
        )
    
    response.headers["Cache-Control"] = "no-store" # as per https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
    
    return await create_tokens_from_authcode_data(authcode_data)

