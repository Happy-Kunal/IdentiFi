from typing import List
from typing_extensions import Annotated
from uuid import uuid4, UUID

from fastapi import APIRouter
from fastapi import Security, Depends
from fastapi import HTTPException, status

from src.crud import CRUDOps
from src.kafka import KafkaProducer, PrincipalUserWorkerDraftEvent
from src.schemas import PrincipalUserInDBSchema, PrincipalUserOutputSchema
from src.security import get_current_user, get_password_hash
from src.types import PrincipalUserTypes
from src.types.scopes import Scopes

from .request_params import PrincipalUserWorkerDraftForm


router = APIRouter(prefix="/principal-user-admin/users")


AdminType = Annotated[
    PrincipalUserInDBSchema,
    Security(get_current_user, scopes=[Scopes.admin])
]

#####################################################################
#                          get methods                              #
#####################################################################

@router.get("/list", response_model=List[PrincipalUserOutputSchema])
async def get_users_in_admins_org(
    admin: AdminType,
    limit: int = 25,
    offset: int = 0
):
    return CRUDOps.get_users_in_principal_user_org(
        client_id=admin.client_id,
        limit=limit,
        offset=offset
    )


@router.get("/email/search", response_model=List[PrincipalUserOutputSchema])
async def search_principal_user_in_admins_org_by_email(
    admin: AdminType,
    q: str,
    limit: int = 25,
    offset: int = 0
):
    return CRUDOps.get_principal_users_with_email_like(
        client_id=admin.client_id,
        q=q,
        limit=limit,
        offset=offset
    )


@router.get("/usernames/search", response_model=List[PrincipalUserOutputSchema])
async def search_principal_user_in_admins_org_by_username(
    admin: AdminType,
    q: str,
    limit: int = 25,
    offset: int = 0
):
    return CRUDOps.get_principal_users_with_username_like(
        client_id=admin.client_id,
        q=q,
        limit=limit,
        offset=offset
    )




#####################################################################
#                            post methods                           #
#####################################################################

@router.post("/create", response_model=PrincipalUserOutputSchema)
async def create_user(
    admin: AdminType,
    form_data: Annotated[PrincipalUserWorkerDraftForm, Depends()]
):
    draft_worker = PrincipalUserInDBSchema(
        client_id=admin.client_id,
        user_id=uuid4(),
        email=form_data.email,
        username=form_data.username,
        preferred_name=form_data.username,
        org_name=admin.org_name,
        user_type=PrincipalUserTypes.PRINCIPAL_USER_WORKER,
        hashed_password=get_password_hash(form_data.password or "")
    )
    
    response = CRUDOps.create_principal_user_worker_draft(draft_worker=draft_worker)

    # publishing event for other microservices like email-microservice
    await KafkaProducer.publish(PrincipalUserWorkerDraftEvent) 

    return response


@router.post("/demote", response_model=PrincipalUserOutputSchema)
async def demote_principal_user_admin(
    admin: AdminType,
    worker_id: UUID
):
    # TODO: implement admin power levels safeguards inorder to avoid
    # junior admin accidentally demoting senior admin
    return CRUDOps.demote_principal_user_admin(
        client_id=admin.client_id,
        admin_id=worker_id
    )


@router.post("/promote", response_model=PrincipalUserOutputSchema)
async def promote_principal_user_worker(
    admin: AdminType,
    worker_id: UUID
):
    return CRUDOps.promote_principal_user_worker(
        client_id=admin.client_id,
        worker_id=worker_id
    )




#####################################################################
#                           delete methods                          #
#####################################################################

@router.delete("/delete")
async def delete_principal_user_worker(
    admin: AdminType,
    worker_id: UUID
):
    worker = CRUDOps.get_principal_user_by_user_id(
        client_id=admin.client_id,
        user_id=worker_id
    )

    if (worker.user_type == PrincipalUserTypes.PRINCIPAL_USER_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="can't delete admin directly, try demoting to worker before deleting"
        )
    
    CRUDOps.delete_principal_user(worker)

