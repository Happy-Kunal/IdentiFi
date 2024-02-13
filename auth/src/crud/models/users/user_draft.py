from uuid import uuid4

from cassandra.cqlengine import columns
from cassandra.cqlengine import ValidationError
from cassandra.cqlengine.models import Model

from src.types import UserType


class UserDraft(Model):
    __table_name__ = "user_draft"

    org_identifier  = columns.Text(required=True, partition_key=True, min_length=6, max_length=255)
    user_id         = columns.UUID(required=True, primary_key=True, default=uuid4)

    username        = columns.Text(required=True, min_length=6, max_length=255)
    email           = columns.Text(required=True, min_length=3, max_length=255) # https://stackoverflow.com/a/1423203 https://stackoverflow.com/a/574698
    name            = columns.Text(required=True, min_length=6, max_length=255)
    hashed_password = columns.Text(required=True, max_length=255)
    user_type       = columns.Text(required=True, discriminator_column=True)

    
class AdminUserDraft(UserDraft):
    __discriminator_value__ = UserType.ADMIN_USER.value

class WorkerUserDraft(UserDraft):
    __discriminator_value__ = UserType.WORKER_USER.value

