from uuid import UUID

from pydantic import BaseModel, Field
from pydantic import ConfigDict
from pydantic import field_serializer
from pydantic import EmailStr

from src.types import UserType


class ServiceProviderBaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    username: str = Field(min_length=6, max_length=255, pattern=r"^\S+$")
    email: EmailStr

    @property
    def user_type(self) -> UserType:
        return UserType.SERVICE_PROVIDER

class ServiceProviderInputSchema(ServiceProviderBaseSchema):
    password: str

class ServiceProviderOutputSchema(ServiceProviderBaseSchema):
    pass

class ServiceProviderInDBSchema(ServiceProviderOutputSchema):
    client_id: UUID
    client_secret: str
    hashed_password: str
