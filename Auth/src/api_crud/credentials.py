from typing import Annotated

from fastapi import APIRouter
from fastapi import Security

from src.crud import CRUDOps
from src.schemas import PrincipalUserInDBSchema, ServiceProviderInDBSchema
from src.security.utils import get_current_user
from src.types.scopes import Scopes

from .response import FIDResponse, ServiceProviderClientID, ClientSecretResetResponse


router = APIRouter()


AdminType = Annotated[
    PrincipalUserInDBSchema,
    Security(get_current_user, scopes=[Scopes.admin])
]

ServiceProviderType = Annotated[
    ServiceProviderInDBSchema,
    Security(get_current_user, scopes=[Scopes.service_provider])
]

#####################################################################
#                principal-user-admin related methods               #
#####################################################################

@router.get("/principal-user-admin/credentials/get-fid", response_model=FIDResponse)
async def get_fid(
    admin: AdminType
):
    return FIDResponse(fid=admin.client_id)




#####################################################################
#                  service_provider related methods                 #
#####################################################################

@router.get("/service_provider/credentials/client-id", response_model=ServiceProviderClientID)
async def get_client_id(
    service_provider: ServiceProviderType
):
    return ServiceProviderClientID(client_id=service_provider.client_id)


@router.post("/service-provider/credentials/secrets/reset", response_model=ClientSecretResetResponse)
async def reset_client_secret(
    service_provider: ServiceProviderType
):
    return CRUDOps.reset_service_provider_secret(service_provider=service_provider)
