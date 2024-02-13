from typing  import Annotated, Any, Dict
from typing_extensions import Annotated, Doc

from fastapi import Security
from fastapi import HTTPException, status

from src.schemas import UserInDBSchema, ServiceProviderInDBSchema
from src.security import get_current_user
from src.types.scopes import Scopes



AdminType = Annotated[
    UserInDBSchema,
    Security(get_current_user, scopes=[Scopes.admin])
]

PrincipalUserType = Annotated[
    UserInDBSchema,
    Security(get_current_user, scopes=[Scopes.worker])
]

ServiceProviderType = Annotated[
    ServiceProviderInDBSchema,
    Security(get_current_user, scopes=[Scopes.service_provider])
]


class DoesNotBelongsToException(HTTPException):
    def __init__(self, org_identifier: str):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"current logged in user doesn't belongs to {org_identifier}"
        )

class CanNotPromoteOrDemoteSelfException(HTTPException):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="users can't promote or demote themself",
        )
