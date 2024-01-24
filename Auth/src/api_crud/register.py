from typing_extensions import Annotated
from uuid import uuid4

from fastapi import APIRouter
from fastapi import Depends

from src.crud import CRUDOps
from src.schemas import PrincipalUserInDBSchema, PrincipalUserOutputSchema, ServiceProviderInDBSchema, ServiceProviderOutputSchema
from src.security.utils import get_password_hash
from src.types import PrincipalUserTypes
from src.models import secret_maker

from .request_params import PrincipalUserAdminRegistrationForm, ServiceProviderRegistrationForm


router = APIRouter()


#####################################################################
#                principal-user-admin related methods               #
#####################################################################

@router.post("/principal-user-admin/register", response_model=PrincipalUserOutputSchema)
async def register_principal_user_admin(
    form_data: Annotated[PrincipalUserAdminRegistrationForm, Depends()]
):

    admin = PrincipalUserInDBSchema(
        client_id=uuid4(),
        user_id=uuid4(),
        email=form_data.email,
        username=form_data.username,
        preferred_name=form_data.preferred_name,
        org_name=form_data.org_name,
        user_type=PrincipalUserTypes.PRINCIPAL_USER_ADMIN,
        hashed_password=get_password_hash(form_data.password)
    )

    return CRUDOps.create_principal_user_admin(admin, org_identifier=form_data.org_identifier)



#####################################################################
#                  service_provider related methods                 #
#####################################################################

@router.post("/service_provider/register", response_model=ServiceProviderOutputSchema)
async def register_service_provider(
    form_data: Annotated[ServiceProviderRegistrationForm, Depends()]
):
    service_provider = ServiceProviderInDBSchema(
        client_id=uuid4(),
        email=form_data.email,
        username=form_data.username,
        org_name=form_data.org_name,
        client_secret=secret_maker.make_secret(),
        hashed_password=get_password_hash(form_data.password)
    )

    return CRUDOps.create_service_provider(service_provider=service_provider)

