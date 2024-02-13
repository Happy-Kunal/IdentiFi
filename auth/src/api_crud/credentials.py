from typing import Annotated

from fastapi import APIRouter

from src.crud import CRUDOps

from .response import ServiceProviderClientID, ClientSecretResetResponse
from .utils import ServiceProviderType, PrincipalUserType


router = APIRouter()


#####################################################################
#                principal-user-admin related methods               #
#####################################################################

@router.get("/{org_identifier}/fid")
async def get_fid(
    _user: PrincipalUserType,
    org_identifier: str
):
    return org_identifier


#####################################################################
#                  service_provider related methods                 #
#####################################################################

@router.get("/service-providers/me/credentials/client-id", response_model=ServiceProviderClientID)
async def get_client_id(
    service_provider: ServiceProviderType
):
    return ServiceProviderClientID(client_id=service_provider.client_id)


@router.post("/service-provider/credentials/secrets/reset", response_model=ClientSecretResetResponse)
async def reset_client_secret(
    service_provider: ServiceProviderType
):
    return CRUDOps.reset_service_provider_secret(username=service_provider.username)
