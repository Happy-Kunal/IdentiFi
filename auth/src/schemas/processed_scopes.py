from pydantic import BaseModel

from src.types import UserType
from src.types.scopes import Scopes


class ProcessedScopes(BaseModel):
    user_type: UserType
    scopes: list[Scopes]
