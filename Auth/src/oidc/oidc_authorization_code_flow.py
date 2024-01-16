import logging
import urllib.parse
from typing import Union, List, Set, cast, Dict, Any
from typing_extensions import Annotated
from uuid import UUID
from secrets import compare_digest
from datetime import datetime, timezone, timedelta

from pydantic import HttpUrl
from fastapi import APIRouter
from fastapi import Depends
from fastapi import Request, Response
from fastapi import HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer

from jose import jwe
from jose.exceptions import JWEError

from src.crud.crud_ops import CRUDOps
from src.schemas.principal_user import PrincipalUserInDBSchema
from src.schemas.token import (
    AccessTokenData,
    OIDCAccessTokenData,
    OIDCRefreshTokenData,
    OIDCIDTokenData,
    OIDCTokenResponse,
)
from src.security.exceptions import not_enough_permission_exception
from src.security.utils import (
    encode_to_jwt_token as encode_to_jwt_token_same_site,
    decode_jwt_token    as decode_jwt_token_same_site,
    oauth2_scheme       as user_jwt_access_token_getter_async
)
from src.types.scopes import OIDCScopes
from src.types.user_types import UserType

from .request_parameters import OAuth2AuthorizationCodeRequestForm, OAuth2AuthorizationCodeRequestQuery
from .authorization_code_data import AuthorizationCodeData
from .authorization_code_token_request import AuthorizationCodeTokenRequestParams


LOGIN_ENDPOINT = "http://127.0.0.1:8000/login"
JWE_KEY_MANAGEMENT_ALGORITHM = "dir"
JWE_ENCRYPT_ALGORITHM = "A256GCM"
JWE_SECRET_KEY = "<JWE_SECRET_KEY><JWE_SECRET_KEY>" #256 bits (32 chars)
AUTHORIZATION_CODE_EXP_TIME_IN_MINUTES = 2
OIDC_JWT_SIGNING_ALGORITHM = "RS256" # RSA
OIDC_JWT_SIGNING_PRIVATE_KEY = "<PRIVATE_SECRET_KEY>" # openssl genpkey -algorithm RSA -out private_key.pem
OIDC_JWT_SIGNING_PUBLIC_KEY = "<PUBLIC_SECRET_KEY>" # openssl rsa -pubout -in private_key.pem -out public_key.pem
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 24 * 60 # 24 hours
ID_TOKEN_EXPIRE_MINUTES = 10
ISSUER = "http://127.0.0.1:8000/"



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


def encode_to_jwt_token_oidc(data: Dict[str, Any]) -> str:
    return encode_to_jwt_token_same_site(
        data=data,
        algorithm=OIDC_JWT_SIGNING_ALGORITHM,
        private_key=OIDC_JWT_SIGNING_PRIVATE_KEY
    )


def decode_jwt_token_oidc(token: str) -> Dict[str, Any]:
    return decode_jwt_token_same_site(
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


async def get_logged_in_user(access_token: str) -> Union[PrincipalUserInDBSchema, None]:
    token_data = AccessTokenData(**decode_jwt_token_same_site(access_token))
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


async def authenticate_client_async(client_id: UUID, client_secret: Union[str, None] = None):
    client = CRUDOps.get_service_provider_by_client_id(client_id)
    if (client):
        return client_secret is None or compare_digest(client.client_secret, client_secret)
    
    return False


async def is_consent_form_required(user: PrincipalUserInDBSchema, client_id: UUID, scopes: List[OIDCScopes]):
    granted_scopes: Set[OIDCScopes] = CRUDOps.get_scopes_granted_by_user_to_client(
                                            user_id=user.user_id,
                                            user_client_id=user.client_id,
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
    user: PrincipalUserInDBSchema,
    client_id: UUID,
    redirect_uri: HttpUrl,
    scopes: List[OIDCScopes]
) -> str:
    authorization_code_data = AuthorizationCodeData(
        sub=f"{user.client_id}:{user.username}",
        redirect_uri=redirect_uri,
        scopes=scopes,
        client_id=client_id,
        exp=datetime.now(timezone.utc) + timedelta(minutes=AUTHORIZATION_CODE_EXP_TIME_IN_MINUTES)
    )

    authorization_code = encrypt_string(
        encode_to_jwt_token_oidc(
            authorization_code_data.model_dump()
        )
    )

    return authorization_code


async def create_tokens_from_authcode_data(authcode_data: AuthorizationCodeData) -> OIDCTokenResponse:
    common = {
        "aud": authcode_data.client_id, # client_id of client [service-provider]
        "fid": authcode_data.sub.partition(":")[0], # sub := `<user.client_id: UUID>:<user.username: str>`
        "iss": ISSUER,
        "sub": authcode_data.sub,
        
        "scopes": authcode_data.scopes,
        "user_type": UserType.OIDC_CLIENT,
    }
    
    access_token = OIDCAccessTokenData(
        **common,
        exp=datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    refresh_token = OIDCRefreshTokenData(
        **common,
        exp=datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES),
    )

    id_token = OIDCIDTokenData(
        **common,
        iat=datetime.now(timezone.utc),
        exp=datetime.now(timezone.utc) + timedelta(minutes=ID_TOKEN_EXPIRE_MINUTES)
    )

    if (len(authcode_data.scopes) > 1):
        client_id, _, username = authcode_data.sub.partition(":")
        user = CRUDOps.get_prinicipal_user_by_username(client_id=client_id, username=username)

        if (OIDCScopes.profile in authcode_data.scopes):
            id_token.name = user.preferred_name # TODO: make variable naming scheme consistent with OIDC claims for id token
            id_token.preferred_username = user.username # TODO: make variable naming scheme consistent with OIDC claims for id token
        
        if (OIDCScopes.email in authcode_data.scopes):
            id_token.email = user.email

    return OIDCTokenResponse(
        token_type="Bearer",
        access_token=encode_to_jwt_token_oidc(access_token.model_dump()),
        refresh_token=encode_to_jwt_token_oidc(refresh_token.model_dump()),
        id_token=encode_to_jwt_token_oidc(id_token.model_dump(exclude_none=True)),
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )




@router.get("/authorize")
async def authorize(
    request: Request,
    query_data: Annotated[OAuth2AuthorizationCodeRequestQuery, Depends()],
):
    try:
        access_token = await user_jwt_access_token_getter_async(request=request)
    except HTTPException:
        access_token = request.cookies.get("access_token")
        if (not access_token):
            return await display_login_screen(redirect_uri=request.url._url)
    
    user = await get_logged_in_user(access_token=access_token)

    if (not user):
        return await display_login_screen(redirect_uri=request.url._url)
    elif (not await authenticate_client_async(client_id=query_data.client_id)):
        raise invalid_client_id_exception
    elif (await is_consent_form_required(user=user, client_id=query_data.client_id, scopes=query_data.scopes)):
        return await send_consent_form(redirect_uri=request.url._url)
    else:
        auth_code = await generate_authorization_code(
            user=user,
            client_id=query_data.client_id,
            redirect_uri=query_data.redirect_uri,
            scopes=query_data.scopes
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
        **decode_jwt_token_oidc(
            token=decrypt_string(params.code)
        )
    )

    if (not await authenticate_client_async(client_id=params.client_id, client_secret=params.client_secret)):
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

