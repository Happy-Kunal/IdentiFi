from pydantic import BaseModel

from src.types.user_types import UserType

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    sub: str
    user_type: UserType
    iss: str
