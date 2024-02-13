import uuid

from cassandra.cqlengine import columns
from cassandra.cqlengine.models import Model

from src.commons import secret_maker


class ServiceProviderByUsername(Model):
    __table_name__ = "service_provide_by_username"

    username        = columns.Text(primary_key=True, min_length=6, max_length=255)    
    
    hashed_password = columns.Text(required=True, min_length=1, max_length=255)
    email           = columns.Text(required=True, min_length=3, max_length=255)

    client_id       = columns.UUID(required=True, default=uuid.uuid4)
    client_secret   = columns.Text(required=True, default=secret_maker.make_secret)


class ServiceProviderByClientID(Model):
    __table_name__ = "service_provide_by_client_id"

    client_id       = columns.UUID(primary_key=True, default=uuid.uuid4)
    
    username        = columns.Text(required=True, min_length=6, max_length=255)    
    hashed_password = columns.Text(required=True, min_length=1, max_length=255)
    email           = columns.Text(required=True, min_length=3, max_length=255)

    client_secret   = columns.Text(required=True, default=secret_maker.make_secret)

