import logging
import urllib.parse
from typing import Union, List, Set, cast
from typing_extensions import Annotated
from uuid import UUID
from secrets import compare_digest
from datetime import datetime, timezone, timedelta

from pydantic import HttpUrl
from fastapi import APIRouter
from fastapi import Depends, Cookie
from fastapi import Request
from fastapi import HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer

from jose import jwe
from jose.exceptions import JWEError

from src.schemas.principal_user import PrincipalUserInDBSchema
from src.crud.crud_ops import CRUDOps
from src.security.exceptions import not_enough_permission_exception
from src.security.utils import encode_to_jwt_token, decode_jwt_token
from src.schemas.token import AccessTokenData
from src.types.user_types import UserType
from src.security.utils import oauth2_scheme as user_jwt_access_token_getter_async

from .oidc_scopes import OIDCScopes
from .request_parameters import OAuth2AuthorizationCodeRequestForm, OAuth2AuthorizationCodeRequestQuery
from .authorization_code_data import AuthorizationCodeData
from .authorization_code_token_request import AuthorizationCodeTokenRequestParams


LOGIN_ENDPOINT = "http://localhost:8000/login"
JWE_KEY_MANAGEMENT_ALGORITHM = "dir"
JWE_ENCRYPT_ALGORITHM = "A256GCM"
JWE_SECRET_KEY = "<JWE_SECRET_KEY><JWE_SECRET_KEY>" #256 bits (32 chars)
AUTHORIZATION_CODE_EXP_TIME_IN_MINUTES = 2

logger = logging.getLogger(__name__)


scopes = {
    OIDCScopes.openid: "to obtain id token",
    OIDCScopes.profile: "allow access to user's username, preferred_name, user_id",
    OIDCScopes.email: "allow access to user's email",
    OIDCScopes.service_provider_config: "allow access to user's service-provider-config"
                    " for client whom token is issued set by admin of principal-user (if any)"
}


oauth2_authorization_code_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="/oauth2/authorize",
    tokenUrl="/oauth2/token",
    refreshUrl="/oauth2/refresh",
    scopes=scopes
)


invalid_client_id_exception = HTTPException(
    status_code=status.HTTP_406_NOT_ACCEPTABLE,
    detail="invalid client_id: no such client exists with given client_id"
)


router = APIRouter(prefix="/oauth2")

def encrypt_string(data: str) -> str:
    return jwe.encrypt(data, key=JWE_SECRET_KEY, encryption=JWE_ENCRYPT_ALGORITHM, algorithm=JWE_KEY_MANAGEMENT_ALGORITHM).decode("utf-8")

def decrypt_string(data: str):
    try:
        return jwe.decrypt(data, key=JWE_SECRET_KEY)
    except JWEError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid authorization_code",
        )

async def get_logged_in_user(access_token: str) -> Union[PrincipalUserInDBSchema, None]:
    token_data = AccessTokenData(**decode_jwt_token(access_token))
    client_id, _, username = token_data.sub.partition(":")
    if (token_data.user_type == UserType.PRINCIPAL_USER):
        user = CRUDOps.get_prinicipal_user_by_username(client_id, username)
    else:
        raise not_enough_permission_exception()
    
    return user



async def display_login_screen(redirect_uri: HttpUrl):
    quoted_redirect_uri = urllib.parse.quote(redirect_uri)
    return RedirectResponse(
        url=f"{LOGIN_ENDPOINT}?redirect_uri={quoted_redirect_uri}",
        status_code=status.HTTP_302_FOUND
    )


async def are_valid_client_credentials(client_id: UUID, client_secret: Union[str, None] = None):
    client = CRUDOps.get_service_provider_by_client_id(client_id)
    if (client):
        return client_secret is None or compare_digest(client.client_secret, client_secret)
    
    return False


async def is_consent_form_required(user: PrincipalUserInDBSchema, client_id: UUID, scopes: List[OIDCScopes]):
    granted_scopes: Set[OIDCScopes] = CRUDOps.get_scopes_granted_by_user_to_client(user_id=user.user_id, user_client_id=user.client_id, client_id=client_id)

    for scope in scopes:
        if (scope not in granted_scopes):
            return True
    
    return False


async def send_consent_form(redirect_uri: HttpUrl):
    # TODO: add consent functionality
    return NotImplemented

async def generate_authorization_code(user: PrincipalUserInDBSchema, client_id: UUID, redirect_uri: HttpUrl, scopes: List[OIDCScopes]) -> str:
    authorization_code_data = AuthorizationCodeData(
        sub=f"{user.client_id}:{user.username}",
        redirect_uri=redirect_uri,
        scopes=scopes,
        client_id=client_id,
        exp=datetime.now(timezone.utc) + timedelta(minutes=AUTHORIZATION_CODE_EXP_TIME_IN_MINUTES)
    )

    authorization_code = encrypt_string(encode_to_jwt_token(authorization_code_data.model_dump()))

    return authorization_code
    

@router.get("/authorize")
async def authorize(
    request: Request,
    query_data: Annotated[OAuth2AuthorizationCodeRequestQuery, Depends()],
):
    try:
        access_token = await user_jwt_access_token_getter_async(request=request)
    except HTTPException:
        access_token = request.cookies.get("access_token")
        print(access_token)
        if (not access_token):
            return await display_login_screen(redirect_uri=request.url._url)
    

    user = await get_logged_in_user(access_token=access_token)

    if (not user):
        return await display_login_screen(redirect_uri=request.url._url)
    elif (not await are_valid_client_credentials(client_id=query_data.client_id)):
        raise invalid_client_id_exception
    elif (await is_consent_form_required(user=user, client_id=query_data.client_id, scopes=query_data.scopes)):
        return await send_consent_form(redirect_uri=request.url._url)
    else:
        auth_code = await generate_authorization_code(user=user, client_id=query_data.client_id, redirect_uri=query_data.redirect_uri, scopes=query_data.scopes)

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

@router.post("/token")
async def token_from_authorization_code(params: AuthorizationCodeTokenRequestParams):
    # TODO: replace temporary implementation with one that fits OAuth2 Logic
    return {
        "code_data": decode_jwt_token(decrypt_string(params.code)),
        "params": {
            "grant_type": params.grant_type,
            "code": params.code,
            "redirect_uri": params.redirect_uri,
            "client_id": params.client_id,
            "client_secret": params.client_secret,
        }
    }