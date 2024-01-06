import uuid

from cassandra.cqlengine import columns
from cassandra.cqlengine.models import Model
from cassandra.cqlengine import ValidationError

from src.types.user_types import PrincipalUserTypes


class PrincipalUserModel(Model):
    __table_name__ = "principal_user"
    client_id          = columns.UUID(partition_key=True, default=uuid.uuid4)
    user_id         = columns.UUID(primary_key=True, default=uuid.uuid4)
    email           = columns.Text(primary_key=True, required=True)
    username        = columns.Text(primary_key=True, required=True, index=True, min_length=6, max_length=255)
    
    preferred_name  = columns.Text(required=True, index=True, min_length=2, max_length=255)
    org_name        = columns.Text(required=True, index=True, min_length=6, max_length=255)
    user_type       = columns.Text(discriminator_column=True, required=True)

    hashed_password = columns.Text(required=True, max_length=255)

    def validate(self):
        super(PrincipalUserModel, self).validate()
        
        valid_user_types = [user_type.value for user_type in PrincipalUserTypes]
        if (self.user_type not in valid_user_types):
            raise ValidationError(f"user_type: {self.user_type} not in valid_user_types: {valid_user_types}")
        


class PrincipalUserAdminModel(PrincipalUserModel):
    __discriminator_value__ = PrincipalUserTypes.PRINCIPAL_USER_ADMIN


class PrincipalUserWorkerModel(PrincipalUserModel):
    __discriminator_value__ = PrincipalUserTypes.PRINCIPAL_USER_WORKER

