from datetime import datetime, timedelta
from typing_extensions import Annotated

from fastapi import APIRouter, HTTPException, status
from fastapi import Depends, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from jose import jwt, JWTError
from passlib.context import CryptContext


from src.types.user_types import UserType
from src.crud.crud_ops import CRUDOps
from src.schemas.token import Token, TokenData

SECRET_KEY = "<SECRET_KEY>"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


scopes = {
    UserType.PRINCIPAL_USER: f"Allow all permissions related to admin of {UserType.PRINCIPAL_USER}",
    UserType.SERVICE_PROVIDER: f"Allow all permissions related to admin of {UserType.SERVICE_PROVIDER}"
}


password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", scopes=scopes)


router = APIRouter(prefix="/auth")


invalid_token_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Incorrect username or password",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_password_hash(password: str) -> str:
    return password_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return password_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str, user_type: UserType):
    if (user_type == UserType.PRINCIPAL_USER):
        user = CRUDOps.get_prinicipal_user_by_username(username)
    else:
        user = CRUDOps.get_service_provider_by_username(username)

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


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise invalid_token_exception
        token_data: TokenData = TokenData(**payload)
    except JWTError:
        raise invalid_token_exception
    
    if (token_data.user_type == UserType.PRINCIPAL_USER):
        user = CRUDOps.get_prinicipal_user_by_username(username)
    else:
        user = CRUDOps.get_service_provider_by_username(username)
    
    if user is None:
        raise invalid_token_exception
    
    return user


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
):
    user_type = UserType.PRINCIPAL_USER if UserType.PRINCIPAL_USER in form_data.scopes else UserType.SERVICE_PROVIDER
    user = authenticate_user(form_data.username, form_data.password, user_type)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "user_type": user_type, "iss": "localhost"}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

