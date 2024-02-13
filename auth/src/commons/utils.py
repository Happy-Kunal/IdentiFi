from typing import Any
from uuid import UUID

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import ValidationError

from src.config import cfg

from .exceptions import InvalidTokenException


HTTPS_ONLY_COOKIE = cfg.cookies.https_only


password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def decode_jwt_token(token: str, algorithms: list[str], public_key: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, public_key, algorithms=algorithms)
        sub: str = payload.get("sub")
        if sub is None:
            raise InvalidTokenException
        return payload
    except (JWTError, ValidationError):
        raise InvalidTokenException


def encode_to_jwt_token(data: dict[str, Any], algorithm: str, private_key: str) -> str:
    encoded_jwt = jwt.encode(data.copy(), private_key, algorithm=algorithm)
    return encoded_jwt


def get_password_hash(password: str) -> str:
    return password_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return password_context.verify(plain_password, hashed_password)


def encode_sub_for_principal_user(org_identifier: str, user_id: UUID) -> str:
    return f"{org_identifier}:{user_id}"

def decode_sub_for_principal_user(sub: str) -> tuple[str, UUID]:
    org_identifier, _, user_id = sub.partition(":")
    return org_identifier, UUID(user_id)


