from .syncer import CassandraSyncer

from ..models.principal_user_model import PrincipalUserModel
from ..models.service_provider_model import ServiceProviderModel

UPDATE_DB_SCHEMA = True

CASSANDRA_HOSTS = ["localhost"]
CASSANDRA_KEYSPACE = "identifi_auth"
CASSANDRA_PROTOCOL_VERSION = 3

models = [
    PrincipalUserModel,
    ServiceProviderModel,
]

if UPDATE_DB_SCHEMA:
    syncer = CassandraSyncer()
    syncer.sync(models=models)


class CRUDOps:
    pass