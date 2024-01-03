import uuid

from pydantic import BaseModel
from pydantic import EmailStr


class ServiceProviderBaseSchema(BaseModel):
    client_id: uuid.UUID
    email: EmailStr
    username: str
    org_name: str

class ServiceProviderInputSchema(ServiceProviderBaseSchema):
    password: str

class ServiceProviderInDBSchema(ServiceProviderBaseSchema):
    client_secret: str
    hashed_password: str

class ServiceProviderOutputSchema(ServiceProviderBaseSchema):
    pass
