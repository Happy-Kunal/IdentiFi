import uuid

from cassandra.cqlengine import columns
from cassandra.cqlengine.models import Model

from . import secret_maker


class ServiceProviderModel(Model):
    __table_name__ = "service_provide"

    client_id       = columns.UUID(partition_key=True, default=uuid.uuid4)
    email           = columns.Text(primary_key=True, required=True)
    username        = columns.Text(primary_key=True, required=True, index=True, min_length=6, max_length=255)    
    org_name        = columns.Text(required=True, index=True, min_length=6, max_length=255)

    hashed_password = columns.Text(required=True, max_length=255)
    client_secret   = columns.Text(required=True, default=secret_maker.make_secret)
