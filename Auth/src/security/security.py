from typing import List
from uuid import UUID
from datetime import datetime, timedelta
from typing_extensions import Annotated


from pydantic import ValidationError
from fastapi import APIRouter, HTTPException, status
from fastapi import Depends, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from jose import jwt, JWTError
from passlib.context import CryptContext


from src.types.user_types import UserType, PrincipalUserTypes
from src.types.scopes import Scopes
from src.crud.crud_ops import CRUDOps
from src.schemas.token import Token, TokenData
from src.schemas.processed_scopes import ProcessedScopes
from .exceptions import credentials_exception, invalid_scopes_selection_exception, invalid_token_exception


SECRET_KEY = "<SECRET_KEY>"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
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


def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def process_scopes(scopes: List[Scopes]) -> ProcessedScopes:
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
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise invalid_token_exception
        token_data: TokenData = TokenData(**payload)
    except (JWTError, ValidationError):
        raise invalid_token_exception

    if (token_data.user_type == UserType.PRINCIPAL_USER):
        user = CRUDOps.get_prinicipal_user_by_username(token_data.org_id, username)
    else:
        user = CRUDOps.get_service_provider_by_username(token_data.org_id, username)

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


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
):
    processed_scopes: ProcessedScopes = process_scopes(form_data.scopes)
    
    try:
        org_id = UUID(form_data.client_id)
    except ValueError:
        raise credentials_exception
    
    user = authenticate_user(org_id, form_data.username, form_data.password, processed_scopes.user_type)

    if (processed_scopes.user_type == UserType.PRINCIPAL_USER and Scopes.admin in processed_scopes.scopes and user.user_type != PrincipalUserTypes.PRINCIPAL_USER_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not enough permissions",
            headers={
                "WWW-Authenticate": f'Bearer scopes="{" ".join(processed_scopes.scopes)}"'},
        )
    

    data = TokenData(
        org_id=org_id,
        sub=user.username,
        scopes=processed_scopes.scopes,
        user_type=processed_scopes.user_type,
        iss=ISSUER
    )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data=data.model_dump(), expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}
