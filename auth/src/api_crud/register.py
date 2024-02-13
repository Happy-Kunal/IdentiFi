from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends

from src.crud import CRUDOps
from src.schemas import UserInputSchema, UserOutputSchema, ServiceProviderInputSchema, ServiceProviderOutputSchema
from src.types import UserType

from .request_params import PrincipalUserAdminRegistrationForm, ServiceProviderRegistrationForm


router = APIRouter()


#####################################################################
#                principal-user-admin related methods               #
#####################################################################

@router.post("/register/principal-user-admin", response_model=UserOutputSchema)
async def register_principal_user_admin(
    form_data: Annotated[PrincipalUserAdminRegistrationForm, Depends()]
):

    admin = UserInputSchema(
        org_identifier=form_data.org_identifier,
        username=form_data.username,
        email=form_data.email,
        name=form_data.preferred_name,
        user_type=UserType.ADMIN_USER,
        password=form_data.password
    )

    return CRUDOps.create_user(user=admin)



#####################################################################
#                  service_provider related methods                 #
#####################################################################

@router.post("/register/service-provider", response_model=ServiceProviderOutputSchema)
async def register_service_provider(
    form_data: Annotated[ServiceProviderRegistrationForm, Depends()]
):
    service_provider = ServiceProviderInputSchema(
        username=form_data.username,
        email=form_data.email,
        password=form_data.password,
    )

    return CRUDOps.create_service_provider(service_provider=service_provider)

