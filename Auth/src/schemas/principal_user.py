from uuid import UUID

from pydantic import BaseModel
from pydantic import field_serializer
from pydantic import EmailStr

from src.types.user_types import PrincipalUserTypes

class PrincipalUserBaseSchema(BaseModel):
    client_id: UUID
    user_id: UUID
    email: EmailStr
    username: str
    preferred_name: str
    org_name: str
    user_type: PrincipalUserTypes


    @field_serializer("client_id")
    def serialize_client_id(self, client_id: UUID, _info):
        return str(client_id)
    
    @field_serializer("user_id")
    def serialize_user_id(self, user_id: UUID, _info):
        return str(user_id)


class PrincipalUserInputSchema(PrincipalUserBaseSchema):
    password: str

class PrincipalUserInDBSchema(PrincipalUserBaseSchema):
    hashed_password: str

class PrincipalUserOutputSchema(PrincipalUserBaseSchema):
    pass
