from uuid import UUID

from pydantic import BaseModel, Field
from pydantic import field_serializer
from pydantic import EmailStr


from src.types.user_types import ServiceProviderTypes

class ServiceProviderBaseSchema(BaseModel):
    client_id: UUID
    email: EmailStr
    username: str
    org_name: str
    user_type: ServiceProviderTypes = Field(default=ServiceProviderTypes.SERVICE_PROVIDER)

    @field_serializer("client_id")
    def serialize_client_id(self, client_id: UUID, _info):
        return str(client_id)

class ServiceProviderInputSchema(ServiceProviderBaseSchema):
    password: str

class ServiceProviderInDBSchema(ServiceProviderBaseSchema):
    client_secret: str
    hashed_password: str

class ServiceProviderOutputSchema(ServiceProviderBaseSchema):
    pass
