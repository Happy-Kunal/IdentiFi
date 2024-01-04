from typing import List

from pydantic import BaseModel

from src.types.user_types import UserType
from src.types.scopes import Scopes


class ProcessedScopes(BaseModel):
    user_type: UserType
    scopes: List[Scopes]
