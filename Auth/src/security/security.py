from typing import List, Union
from uuid import UUID
from datetime import datetime, timedelta, timezone
from typing_extensions import Annotated


from fastapi import APIRouter
from fastapi import Depends, Form
from fastapi.security import OAuth2PasswordRequestForm


from src.types.user_types import UserType
from src.crud.crud_ops import CRUDOps
from src.schemas.token import Token, AccessTokenData, RefreshTokenData
from src.schemas.processed_scopes import ProcessedScopes

from .exceptions import (
    credentials_exception,
    invalid_token_exception,
    not_enough_permission_exception
)

from .OAuth2PasswordOrRefreshTokenRequestForm import OAuth2PasswordOrRefreshTokenRequestForm

from .utils import (
    authenticate_user,
    decode_jwt_token,
    encode_to_jwt_token,
    is_allowed_to_grant_scopes_to_user,
    process_scopes,
)




ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 24 * 60 # 24 hours
ISSUER = "localhost"


router = APIRouter(prefix="/auth")




async def access_token_using_password_grant(username: str, password: str, scopes: List[str], client_id: str):
    processed_scopes: ProcessedScopes = process_scopes(scopes)
    
    try:
        client_id = UUID(client_id)
    except ValueError:
        raise credentials_exception
    
    user = authenticate_user(client_id, username, password, processed_scopes.user_type)

    if (not is_allowed_to_grant_scopes_to_user(scopes=processed_scopes.scopes, user=user)):
        raise not_enough_permission_exception(scopes=processed_scopes.scopes)
        
    refresh_token_data = RefreshTokenData(
        client_id=client_id,
        sub=user.username,
        user_type=processed_scopes.user_type,
        iss=ISSUER,
        scopes=processed_scopes.scopes,
        exp=datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    )

    refresh_token = encode_to_jwt_token(refresh_token_data.model_dump())
    

    access_token_data = AccessTokenData(
        client_id=client_id,
        sub=user.username,
        user_type=processed_scopes.user_type,
        iss=ISSUER,
        exp=datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        scopes=processed_scopes.scopes
    )
    
    access_token = encode_to_jwt_token(data=access_token_data.model_dump())

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "refresh_token": refresh_token,
        "scope": " ".join(access_token_data.scopes)
    }


async def access_token_using_refresh_token_grant(refresh_token: str):
    refresh_token_data = RefreshTokenData(**decode_jwt_token(refresh_token))
    if (refresh_token_data.user_type == UserType.PRINCIPAL_USER):
        user = CRUDOps.get_prinicipal_user_by_username(refresh_token_data.client_id, refresh_token_data.sub)
    else:
        user = CRUDOps.get_service_provider_by_username(refresh_token_data.client_id, refresh_token_data.sub)

    if (not user):
        raise invalid_token_exception
    elif (not is_allowed_to_grant_scopes_to_user(scopes=refresh_token_data.scopes, user=user)):
        raise not_enough_permission_exception(scopes=refresh_token_data.scopes)


    access_token_data = AccessTokenData(
        client_id=refresh_token_data.client_id,
        sub=refresh_token_data.sub,
        user_type=refresh_token_data.user_type,
        iss=refresh_token_data.iss,
        exp=min(refresh_token_data.exp, datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)),
        scopes=refresh_token_data.scopes
    )

    expires_in = int((access_token_data.exp - datetime.now(timezone.utc)).total_seconds())

    access_token = encode_to_jwt_token(access_token_data.model_dump())

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "refresh_token": refresh_token,
        "scope": " ".join(access_token_data.scopes)
    }


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordOrRefreshTokenRequestForm, Depends()],
):
    if (form_data.grant_type == "password"):
        print(form_data.scopes)
        return await access_token_using_password_grant(
            username=form_data.username,
            password=form_data.password,
            scopes=form_data.scopes,
            client_id=form_data.client_id
        )
    
    else:
        return await access_token_using_refresh_token_grant(form_data.refresh_token)
    

@router.post("/passwordflow/token")
async def login_password_flow(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """
    token endpoint optimized for grant_type=password
    """

    return await access_token_using_password_grant(
        username=form_data.username,
        password=form_data.password,
        scopes=form_data.scopes,
        client_id=form_data.client_id
    )


@router.post("/refresh")
async def login_password_flow(
    *,
    grant_type: Annotated[str, Form(pattern="refresh_token")] = "refresh_token",
    refresh_token: Annotated[str, Form()]
):
    """
    token endpoint optimized for grant_type=refresh_token
    """

    return await access_token_using_refresh_token_grant(refresh_token=refresh_token)

