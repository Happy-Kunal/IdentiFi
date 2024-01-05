from typing import List, Dict, Any
from uuid import UUID
from datetime import datetime, timedelta
from typing_extensions import Annotated


from pydantic import ValidationError
from fastapi import APIRouter, HTTPException, status
from fastapi import Depends, Security
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import jwt, JWTError
from passlib.context import CryptContext


from src.types.user_types import UserType, PrincipalUserTypes
from src.types.scopes import Scopes
from src.crud.crud_ops import CRUDOps

from src.schemas.token import Token, AccessTokenData, RefreshTokenData
from src.schemas.processed_scopes import ProcessedScopes
from .exceptions import credentials_exception, invalid_scopes_selection_exception, invalid_token_exception
from .OAuth2PasswordOrRefreshTokenRequestForm import OAuth2PasswordOrRefreshTokenRequestForm


ALGORITHM = "RS256" # RSA
PRIVATE_KEY = "<PRIVATE_SECRET_KEY>" # openssl genpkey -algorithm RSA -out private_key.pem
PUBLIC_KEY = "<PUBLIC_SECRET_KEY>" # openssl rsa -pubout -in private_key.pem -out public_key.pem
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 24 * 60 # 24 hours
ISSUER = "localhost"


scopes = {
    Scopes.admin: "Allow all permissions related to admin of principal user",
    Scopes.worker: "Allow all permissions related to worker of principal user",
    Scopes.service_provider: "Allow all permissions related to admin of service provider"
}


password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", scopes=scopes)


router = APIRouter(prefix="/auth")


def get_password_hash(password: str) -> str:
    return password_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return password_context.verify(plain_password, hashed_password)


def authenticate_user(org_id: UUID, username: str, password: str, user_type: UserType):
    if (user_type == UserType.PRINCIPAL_USER):
        user = CRUDOps.get_prinicipal_user_by_username(org_id, username)
    else:
        user = CRUDOps.get_service_provider_by_username(org_id, username)

    if (user and verify_password(password, user.hashed_password)):
        return user
    else:
        raise credentials_exception


def encode_to_jwt_token(data: Dict[str, Any]) -> str:
    encoded_jwt = jwt.encode(data.copy(), PRIVATE_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise invalid_token_exception
        return payload
    except (JWTError, ValidationError):
        raise invalid_token_exception




def process_scopes(scopes: List[Scopes]) -> ProcessedScopes:
    print(scopes)
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
    


async def get_current_user(security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]):
    token_data = AccessTokenData(**decode_jwt_token(token))

    if (token_data.user_type == UserType.PRINCIPAL_USER):
        user = CRUDOps.get_prinicipal_user_by_username(token_data.org_id, token_data.sub)
    else:
        user = CRUDOps.get_service_provider_by_username(token_data.org_id, token_data.sub)

    if user is None:
        raise invalid_token_exception

    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            authenticate_value = "Bearer" if not security_scopes.scopes else f'Bearer scope="{security_scopes.scope_str}"'
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )


    return user


async def access_token_using_password_grant(username: str, password: str, scopes: List[str], org_id: str):
    processed_scopes: ProcessedScopes = process_scopes(scopes)
    
    try:
        org_id = UUID(org_id)
    except ValueError:
        raise credentials_exception
    
    user = authenticate_user(org_id, username, password, processed_scopes.user_type)

    if (processed_scopes.user_type == UserType.PRINCIPAL_USER and Scopes.admin in processed_scopes.scopes and user.user_type != PrincipalUserTypes.PRINCIPAL_USER_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not enough permissions",
            headers={
                "WWW-Authenticate": f'Bearer scopes="{" ".join(processed_scopes.scopes)}"'},
        )
    
    refresh_token_data = RefreshTokenData(
        org_id=org_id,
        sub=user.username,
        user_type=processed_scopes.user_type,
        iss=ISSUER,
        exp=datetime.now() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    )

    refresh_token = encode_to_jwt_token(refresh_token_data.model_dump())
    

    access_token_data = AccessTokenData(
        org_id=org_id,
        sub=user.username,
        user_type=processed_scopes.user_type,
        iss=ISSUER,
        exp=datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
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
    access_token_data = AccessTokenData(
        org_id=refresh_token_data.org_id,
        sub=refresh_token_data.sub,
        user_type=refresh_token_data.user_type,
        iss=refresh_token_data.iss,
        exp=datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        # exp=min(refresh_token_data.exp, datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)),# TODO: TypeError: can't compare offset-naive and offset-aware datetimes
        scopes=[] # TODO: access from database
    )

    expires_in = int((access_token_data.exp - datetime.now()).total_seconds())

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
            org_id=form_data.client_id
        )
    
    else:
        return await access_token_using_refresh_token_grant(form_data.refresh_token)
    
