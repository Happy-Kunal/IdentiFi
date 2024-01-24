from typing_extensions import Annotated

from fastapi import APIRouter
from fastapi import Security, Form

from src.crud import CRUDOps
from src.schemas import (PrincipalUserInDBSchema, PrincipalUserOutputSchema,
                         ServiceProviderInDBSchema, ServiceProviderOutputSchema)
from src.security.utils import get_current_user
from src.types.scopes import Scopes


router = APIRouter()


#####################################################################
#                principal-user-admin related methods               #
#####################################################################

@router.delete("/principal-user-admin/unregister", response_model=PrincipalUserOutputSchema)
async def delete_principal_user(
    admin: Annotated[
        PrincipalUserInDBSchema,
        Security(get_current_user, scopes=[Scopes.admin])
    ],
    force: Annotated[bool, Form()] = False
):
    return CRUDOps.delete_principal_user(admin=admin, force=force)




#####################################################################
#                  service_provider related methods                 #
#####################################################################

@router.delete("/service_provider/unregister", response_model=ServiceProviderOutputSchema)
async def delete_service_provider(
    service_provider: Annotated[
        ServiceProviderInDBSchema,
        Security(get_current_user, scopes=[Scopes.service_provider])
    ]
):
    return CRUDOps.delete_service_provider(service_provider=service_provider)

