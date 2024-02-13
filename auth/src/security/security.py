from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from src.config import cfg
from src.crud import CRUDOps
from src.schemas.tokens import AccessTokenData, RefreshTokenData, TokenResponse
from src.types import UserType, Scopes

from src.commons import encode_sub_for_principal_user, decode_sub_for_principal_user
from src.commons.exceptions import (CredentialsException, InvalidTokenException,
                         NotEnoughPermissionException)
from .request_params import OAuth2PasswordOrRefreshTokenRequestParams
from .utils import (authenticate_user, authenticate_service_provider, decode_jwt_token, encode_to_jwt_token,
                    is_allowed_to_grant_scopes_to_user_type, process_scopes,
                    set_tokens_in_cookie)


ACCESS_TOKEN_EXPIRE_TIME = cfg.same_site.exp_time.access_token
ISSUER = cfg.issuer
REFRESH_TOKEN_EXPIRE_TIME = cfg.same_site.exp_time.refresh_token


_security_router_prefix = "/auth"


router = APIRouter(prefix=_security_router_prefix)




async def access_token_using_password_grant(username: str, password: str, scopes: list[str], org_identifier: str | None = None) -> TokenResponse:
    processed_scopes = process_scopes(scopes)
    
    if (Scopes.service_provider in processed_scopes):
        user = authenticate_service_provider(username=username, password=password)
    elif (org_identifier):
        user = authenticate_user(org_identifier=org_identifier, username=username, password=password)
    else:
        raise CredentialsException

    if (user is None):
        raise CredentialsException
    elif (not is_allowed_to_grant_scopes_to_user_type(scopes=processed_scopes, user_type=user.user_type)):
        raise NotEnoughPermissionException(scopes=processed_scopes)
    
    sub = username if user.user_type.is_service_provider() else encode_sub_for_principal_user(org_identifier=org_identifier, user_id=user.user_id)
        
    refresh_token_data = RefreshTokenData(
        sub=sub,
        user_type=user.user_type,
        iss=ISSUER,
        scopes=processed_scopes,
        exp=datetime.now(timezone.utc) + timedelta(seconds=REFRESH_TOKEN_EXPIRE_TIME)
    )

    access_token_data = AccessTokenData(
        sub=sub,
        user_type=user.user_type,
        iss=ISSUER,
        exp=datetime.now(timezone.utc) + timedelta(seconds=ACCESS_TOKEN_EXPIRE_TIME),
        scopes=processed_scopes
    )


    refresh_token = encode_to_jwt_token(refresh_token_data.model_dump())
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

    if (refresh_token_data.user_type.is_principal_user()):
        org_identifier, user_id = decode_sub_for_principal_user(sub=refresh_token_data.sub)
        user = CRUDOps.get_user_by_user_id(org_identifier=org_identifier, user_id=user_id)
    else:
        user = CRUDOps.get_service_provider_by_username(refresh_token_data.sub)

    if (not user):
        raise InvalidTokenException
    elif (not is_allowed_to_grant_scopes_to_user_type(scopes=refresh_token_data.scopes, user_type=user.user_type)):
        # to handle case if logged in admin got demoted to worker after already having valid refresh_token issued earlier
        raise NotEnoughPermissionException(scopes=refresh_token_data.scopes)


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
    set_cookie: bool = False,
    org_identifier: str | None = None
):
    if (form_data.grant_type == "password"):
        token = await access_token_using_password_grant(
            username=form_data.username,
            password=form_data.password,
            scopes=form_data.scopes,
            org_identifier=form_data.client_id or org_identifier
        )

        response.headers["Cache-Control"] = "no-store"

        if(set_cookie): set_tokens_in_cookie(response=response, token=token, cookie_path_for_refresh_token=_security_router_prefix)
        return token
    
    else:
        token = await access_token_using_refresh_token_grant(form_data.refresh_token)

        if(set_cookie): set_tokens_in_cookie(response=response, token=token, cookie_path_for_refresh_token=_security_router_prefix)
        return token
    
    

@router.post("/passwordflow/token")
async def login_password_flow(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    set_cookie: bool = False,
    org_identifier: str | None = None
):
    """
    token endpoint optimized for grant_type=password
    """

    token = await access_token_using_password_grant(
        username=form_data.username,
        password=form_data.password,
        scopes=form_data.scopes,
        org_identifier=form_data.client_id or org_identifier
    )

    response.headers["Cache-Control"] = "no-store"

    if(set_cookie): set_tokens_in_cookie(response=response, token=token, cookie_path_for_refresh_token=_security_router_prefix)
    return token
    


@router.post("/refresh")
async def login_password_flow(
    *,
    request: Request,
    response: Response,
    grant_type: Annotated[str, Form(pattern="refresh_token")] = "refresh_token", # just for compatibility with specs
    refresh_token: Annotated[str | None, Form()] = None,
    set_cookie: bool = False,
):
    """
    token endpoint optimized for grant_type=refresh_token

    our implementation supports setting it through both `cookie` and
    `form` field but if both are present `form` will take precedence.
    """

    token = await access_token_using_refresh_token_grant(refresh_token=refresh_token or request.cookies.get("refresh_token"))

    response.headers["Cache-Control"] = "no-store"

    if(set_cookie): set_tokens_in_cookie(response=response, token=token, cookie_path_for_refresh_token=_security_router_prefix)
    return token
    

