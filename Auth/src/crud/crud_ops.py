from typing import Set
import uuid

from .syncer import CassandraSyncer

from src.models.principal_user_model import PrincipalUserModel
from src.models.service_provider_model import ServiceProviderModel

from src.schemas.principal_user import PrincipalUserInDBSchema
from src.schemas.service_provider import ServiceProviderInDBSchema
from src.oidc.oidc_scopes import OIDCScopes

UPDATE_DB_SCHEMA = False

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
    @staticmethod
    def get_prinicipal_user_by_username(client_id: uuid.UUID, username: str):
        import uuid
        from src.types.user_types import PrincipalUserTypes
        data = {
            "client_id"          : client_id,
            "user_id"         : uuid.uuid4(),
            "email"           : f"{username.replace(' ', '.')}@example.com",
            "username"        : username,
            "preferred_name"  : f"{username}",
            "org_name"        : "example.com",
            "hashed_password" : '$2b$12$cQXJ/inXvNuXyjzenYEA/..TZbhTEkIxTLwkwEywWRjifQG6T.xMK', # brcypt hash of hello
            "user_type"       : PrincipalUserTypes.PRINCIPAL_USER_WORKER
        }

        return PrincipalUserInDBSchema(**data)
    
    @staticmethod
    def get_service_provider_by_username(client_id: uuid.UUID, username: str):
        import uuid
        data = {
            "client_id" : client_id,
            "email" : f"admin@{username.replace(' ', '-')}.com",
            "username" : username,
            "org_name" : username,
            "hashed_password" : '$2b$12$cQXJ/inXvNuXyjzenYEA/..TZbhTEkIxTLwkwEywWRjifQG6T.xMK', # brcypt hash of hello
            "client_secret" : '$2b$12$cQXJ/inXvNuXyjzenYEA/..TZbhTEkIxTLwkwEywWRjifQG6T.xMK' # brcypt hash of hello
        }

        return ServiceProviderInDBSchema(**data)
    
    @staticmethod
    def get_service_provider_by_client_id(client_id):
        return ServiceProviderInDBSchema(
            client_id=client_id,
            email="foobar@example.com",
            username="MrFooBar",
            org_name="Foo Bar & Co.",
            client_secret='$2b$12$cQXJ/inXvNuXyjzenYEA/..TZbhTEkIxTLwkwEywWRjifQG6T.xMK', # brcypt hash of hello
            hashed_password='$2b$12$cQXJ/inXvNuXyjzenYEA/..TZbhTEkIxTLwkwEywWRjifQG6T.xMK', # brcypt hash of hello
        )
    
    @staticmethod
    def get_scopes_granted_by_user_to_client(user_id, user_client_id, client_id):
        return set(OIDCScopes.__members__.keys())
    

        
