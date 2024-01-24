import uuid

from cassandra.cqlengine import columns
from cassandra.cqlengine import ValidationError
from cassandra.cqlengine.models import Model


class PrincipalUserClientIDByOrgUsername(Model):
    __table_name__ = "principal_user_client_id_by_org_username"

    org_username = columns.Text(primary_key=True, min_length=6, max_length=64)
    client_id = columns.UUID(default=uuid.uuid4)

    def validate(self):
        super(PrincipalUserClientIDByOrgUsername, self).validate()
        if (" " in self.org_username):
            raise ValidationError("org username can't have space in them")
    
