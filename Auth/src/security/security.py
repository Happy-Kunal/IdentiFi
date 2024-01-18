from typing import List, Union
from uuid import UUID
from datetime import datetime, timedelta, timezone
from typing_extensions import Annotated


from fastapi import APIRouter
from fastapi import Cookie, Depends, Form
from fastapi import Request, Response
from fastapi.security import OAuth2PasswordRequestForm


from src.config import cfg
from src.types.user_types import UserType
from src.crud.crud_ops import CRUDOps
from src.schemas.token import TokenResponse, AccessTokenData, RefreshTokenData
from src.schemas.processed_scopes import ProcessedScopes

from .exceptions import (
    credentials_exception,
    invalid_token_exception,
    not_enough_permission_exception
)

from .request_params import OAuth2PasswordOrRefreshTokenRequestParams

from .utils import (
    authenticate_user,
    decode_jwt_token,
    encode_to_jwt_token,
    is_allowed_to_grant_scopes_to_user,
    process_scopes,
    set_tokens_in_cookie,
)




ACCESS_TOKEN_EXPIRE_TIME = cfg.same_site.exp_time.access_token
REFRESH_TOKEN_EXPIRE_TIME = cfg.same_site.exp_time.refresh_token
ISSUER = cfg.issuer


router = APIRouter(prefix="/auth")




async def access_token_using_password_grant(username: str, password: str, scopes: List[str], client_id: str) -> TokenResponse:
    processed_scopes: ProcessedScopes = process_scopes(scopes)
    
    try:
        client_id = UUID(client_id)
    except ValueError:
        raise credentials_exception
    
    user = authenticate_user(client_id, username, password, processed_scopes.user_type)

    if (not is_allowed_to_grant_scopes_to_user(scopes=processed_scopes.scopes, user=user)):
        raise not_enough_permission_exception(scopes=processed_scopes.scopes)
        
    refresh_token_data = RefreshTokenData(
        sub=f"{user.client_id}:{user.username}",
        user_type=processed_scopes.user_type,
        iss=ISSUER,
        scopes=processed_scopes.scopes,
        exp=datetime.now(timezone.utc) + timedelta(seconds=REFRESH_TOKEN_EXPIRE_TIME)
    )

    refresh_token = encode_to_jwt_token(refresh_token_data.model_dump())
    

    access_token_data = AccessTokenData(
        sub=f"{user.client_id}:{user.username}",
        user_type=processed_scopes.user_type,
        iss=ISSUER,
        exp=datetime.now(timezone.utc) + timedelta(seconds=ACCESS_TOKEN_EXPIRE_TIME),
        scopes=processed_scopes.scopes
    )
    
    access_token = encode_to_jwt_token(data=access_token_data.model_dump())

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_TIME,
        refresh_token=refresh_token,
        scope=" ".join(access_token_data.scopes)
    )


async def access_token_using_refresh_token_grant(refresh_token: str) -> TokenResponse:
    refresh_token_data = RefreshTokenData(**decode_jwt_token(refresh_token))
    client_id, _, username = refresh_token_data.sub.partition(":")

    if (refresh_token_data.user_type == UserType.PRINCIPAL_USER):
        user = CRUDOps.get_prinicipal_user_by_username(client_id, username)
    else:
        user = CRUDOps.get_service_provider_by_username(client_id, username)

    if (not user):
        raise invalid_token_exception
    elif (not is_allowed_to_grant_scopes_to_user(scopes=refresh_token_data.scopes, user=user)):
        raise not_enough_permission_exception(scopes=refresh_token_data.scopes)


    access_token_data = AccessTokenData(
        sub=refresh_token_data.sub,
        user_type=refresh_token_data.user_type,
        iss=refresh_token_data.iss,
        exp=min(refresh_token_data.exp, datetime.now(timezone.utc) + timedelta(seconds=ACCESS_TOKEN_EXPIRE_TIME)),
        scopes=refresh_token_data.scopes
    )

    expires_in = int((access_token_data.exp - datetime.now(timezone.utc)).total_seconds())

    access_token = encode_to_jwt_token(access_token_data.model_dump())

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        refresh_token=refresh_token,
        scope=" ".join(access_token_data.scopes)
    )


@router.post("/token", response_model=TokenResponse)
async def login_for_access_token(
    response: Response,
    form_data: Annotated[OAuth2PasswordOrRefreshTokenRequestParams, Depends()],
    set_cookie: bool = True,
):
    if (form_data.grant_type == "password"):
        token = await access_token_using_password_grant(
            username=form_data.username,
            password=form_data.password,
            scopes=form_data.scopes,
            client_id=form_data.client_id
        )

        if(set_cookie): set_tokens_in_cookie(response=response, token=token, cookie_path_for_refresh_token="/auth")
        return token
    
    else:
        token = await access_token_using_refresh_token_grant(form_data.refresh_token)

        if(set_cookie): set_tokens_in_cookie(response=response, token=token, cookie_path_for_refresh_token="/auth")
        return token
    
    

@router.post("/passwordflow/token")
async def login_password_flow(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    set_cookie: bool = True,
):
    """
    token endpoint optimized for grant_type=password
    """

    token = await access_token_using_password_grant(
        username=form_data.username,
        password=form_data.password,
        scopes=form_data.scopes,
        client_id=form_data.client_id
    )

    if(set_cookie): set_tokens_in_cookie(response=response, token=token, cookie_path_for_refresh_token="/auth")
    return token
    


@router.post("/refresh")
async def login_password_flow(
    *,
    request: Request,
    response: Response,
    grant_type: Annotated[str, Form(pattern="refresh_token")] = "refresh_token",
    refresh_token: Annotated[str, Form()],
    set_cookie: bool = True,
):
    """
    token endpoint optimized for grant_type=refresh_token

    our implementation supports setting it through both `cookie` and
    `form` field but if both are present `form` will take precedence.
    """

    token = await access_token_using_refresh_token_grant(refresh_token=refresh_token or request.cookies.get("refresh_token"))

    if(set_cookie): set_tokens_in_cookie(response=response, token=token, cookie_path_for_refresh_token="/auth")
    return token
    

