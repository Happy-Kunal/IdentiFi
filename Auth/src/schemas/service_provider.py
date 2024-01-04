from uuid import UUID

from pydantic import BaseModel
from pydantic import field_serializer
from pydantic import EmailStr


class ServiceProviderBaseSchema(BaseModel):
    org_id: UUID
    email: EmailStr
    username: str
    org_name: str

    @field_serializer("org_id")
    def serialize_org_id(self, org_id: UUID, _info):
        return str(org_id)

class ServiceProviderInputSchema(ServiceProviderBaseSchema):
    password: str

class ServiceProviderInDBSchema(ServiceProviderBaseSchema):
    client_secret: str
    hashed_password: str

class ServiceProviderOutputSchema(ServiceProviderBaseSchema):
    pass
