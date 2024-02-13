from uuid import UUID

from pydantic import BaseModel
from pydantic import field_serializer
from pydantic import Base64Str


class ClientSecretResetResponse(BaseModel):
    client_id: UUID
    client_secret: Base64Str


class ServiceProviderClientID(BaseModel):
    client_id: UUID

    @field_serializer("client_id")
    def serialize_client_id(self, client_id: UUID, _info):
        return str(client_id)


