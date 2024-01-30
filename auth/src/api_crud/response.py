from uuid import UUID

from pydantic import BaseModel
from pydantic import Base64Str


class ClientSecretResetResponse(BaseModel):
    client_id: UUID
    client_secret: Base64Str


class FIDResponse(BaseModel):
    fid: UUID


class ServiceProviderClientID(BaseModel):
    client_id: UUID

