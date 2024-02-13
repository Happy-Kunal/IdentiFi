from typing import Annotated

from fastapi import APIRouter

from src.crud import CRUDOps
from src.schemas import (UserOutputSchema, ServiceProviderOutputSchema)

from .utils import ServiceProviderType, PrincipalUserType, DoesNotBelongsToException


router = APIRouter()


#####################################################################
#                principal-user-admin related methods               #
#####################################################################

@router.delete("/{org_identifier}/users/me/unregister", response_model=UserOutputSchema)
async def delete_principal_user(
    user: PrincipalUserType,
    org_identifier: str
):
    if (org_identifier != user.org_identifier):
        raise DoesNotBelongsToException(org_identifier)
    
    return CRUDOps.delete_user(org_identifier=user.org_identifier, user_id=user.user_id)




#####################################################################
#                  service_provider related methods                 #
#####################################################################

@router.delete("/service-providers/me/unregister", response_model=ServiceProviderOutputSchema)
async def delete_service_provider(
    service_provider: ServiceProviderType
):
    return CRUDOps.delete_service_provider(username=service_provider.username)

