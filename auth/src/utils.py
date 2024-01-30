from typing import Annotated

from fastapi import APIRouter
from fastapi import Query
from fastapi import HTTPException, status

from src.crud import CRUDOps
from src.schemas import PrincipalUserClientIDSchema


router = APIRouter(prefix="/principal-user")



@router.get("/client_id", response_model=PrincipalUserClientIDSchema)
async def get_client_id(org_username: Annotated[str, Query(min_length=6, max_length=64)]):
    client_id = CRUDOps.get_principal_user_client_id_by_org_username(org_username=org_username)

    if (client_id):
        return PrincipalUserClientIDSchema(client_id=client_id)
    else:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no organization with org_username={org_username}"
        )



