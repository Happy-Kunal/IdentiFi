from typing  import Annotated, Literal
from uuid import uuid4, UUID

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException, status

from src.crud import CRUDOps
from src.events import KafkaProducer, UserDraftKafkaEventFactory
from src.schemas import UserInputSchema, UserOutputSchema
from src.types import UserType

from .request_params import PrincipalUserDraftForm
from .utils import AdminType, DoesNotBelongsToException, CanNotPromoteOrDemoteSelfException


router = APIRouter()


#####################################################################
#                          get methods                              #
#####################################################################

@router.get("/{org_identifier}/users/list", response_model=list[UserOutputSchema])
async def get_users_in_admins_org(
    admin: AdminType,
    org_identifier: str,
    limit: int = 1000,
    offset: int = 0
):
    if (org_identifier != admin.org_identifier):
        raise DoesNotBelongsToException(org_identifier)
    
    return CRUDOps.get_all_users_by_org_identifier(
        org_identifier=admin.org_identifier,
        limit=limit,
        offset=offset
    )

@router.get("/{org_identifier}/users/search", response_model=list[UserOutputSchema])
async def search_principal_user_in_admins_org_by_email(
    admin: AdminType,
    org_identifier: str,
    by: Literal["email", "username"],
    q: str,
    limit: int = 25,
    offset: int = 0
):
    if (org_identifier != admin.org_identifier):
        raise DoesNotBelongsToException(org_identifier)
    
    if (by == "email"):
        return CRUDOps.get_users_with_email_like(
            org_identifier=admin.org_identifier,
            q=q,
            limit=limit,
            offset=offset
        )
    else:
        return CRUDOps.get_users_with_username_like(
            org_identifier=admin.org_identifier,
            q=q,
            limit=limit,
            offset=offset
        )


#####################################################################
#                            post methods                           #
#####################################################################

@router.post("/{org_identifier}/users/create", response_model=UserOutputSchema)
async def create_user(
    admin: AdminType,
    org_identifier: str,
    form_data: Annotated[PrincipalUserDraftForm, Depends()]
):
    if (org_identifier != admin.org_identifier):
        raise DoesNotBelongsToException(org_identifier)
    
    draft_user = UserInputSchema(
        org_identifier=admin.org_identifier,
        username=form_data.username,
        email=form_data.email,
        name=form_data.username,
        user_type=form_data.user_type,
        password=form_data.password
    )
    
    response = CRUDOps.create_user_draft(draft_user=draft_user)

    # publishing event for other microservices like email-microservice
    # event publishing is internally handled on seprate thread so this will
    # return immediately
    KafkaProducer.publish(UserDraftKafkaEventFactory(response)) 

    return response


@router.post("/{org_identifier}/users/{user_id}/demote", response_model=UserOutputSchema)
async def demote_principal_user_admin(
    admin: AdminType,
    org_identifier: str,
    user_id: UUID
):
    if (org_identifier != admin.org_identifier):
        raise DoesNotBelongsToException(org_identifier)
    elif (user_id == admin.user_id):
        raise CanNotPromoteOrDemoteSelfException
    
    # TODO: implement admin power levels safeguards inorder to avoid
    # junior admin accidentally demoting senior admin
    return CRUDOps.demote_user_to_worker(
        org_identifier=admin.org_identifier,
        user_id=user_id
    )


@router.post("/{org_identifier}/users/{user_id}/promote", response_model=UserOutputSchema)
async def promote_principal_user_worker(
    admin: AdminType,
    org_identifier: str,
    user_id: UUID
):
    if (org_identifier != admin.org_identifier):
        raise DoesNotBelongsToException(org_identifier)
    elif (user_id == admin.user_id):
        raise CanNotPromoteOrDemoteSelfException
    
    return CRUDOps.promote_user_to_admin(
        org_identifier=admin.org_identifier,
        user_id=user_id
    )




#####################################################################
#                           delete methods                          #
#####################################################################

@router.delete("/{org_identifier}/users/{user_id}/delete", response_model=UserOutputSchema)
async def delete_principal_user_worker(
    admin: AdminType,
    org_identifier: str,
    user_id: UUID
):
    if (org_identifier != admin.org_identifier):
        raise DoesNotBelongsToException(org_identifier)
    
    worker = CRUDOps.get_user_by_user_id(
        org_identifier=admin.org_identifier,
        user_id=user_id
    )

    if (worker.user_type is UserType.ADMIN_USER):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="can't delete admin directly, try demoting to worker before deleting"
        )
    
    return CRUDOps.delete_user(org_identifier=admin.org_identifier, user_id=user_id)
