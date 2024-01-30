import uuid

from pydantic import BaseModel
from pydantic import field_serializer


class PrincipalUserClientIDSchema(BaseModel):
    client_id: uuid.UUID

    @field_serializer("client_id")
    def serialize_client_id(self, client_id: uuid.UUID, _info):
        return str(client_id)
