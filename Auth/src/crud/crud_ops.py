from typing import Set
import uuid


from src.config import cfg

from src.models.principal_user_model import PrincipalUserModel
from src.models.service_provider_model import ServiceProviderModel

from src.schemas.principal_user import PrincipalUserInDBSchema
from src.schemas.service_provider import ServiceProviderInDBSchema
from src.types.scopes import OIDCScopes


from .syncer import CassandraSyncer


UPDATE_DB_SCHEMA = cfg.db.schemas.update

CASSANDRA_HOSTS = cfg.db.cassandra.hosts
CASSANDRA_KEYSPACE = cfg.db.cassandra.keyspace
CASSANDRA_PROTOCOL_VERSION = cfg.db.cassandra.protocol_version

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
            "user_type"       : PrincipalUserTypes.PRINCIPAL_USER_ADMIN
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
    def get_principal_user_by_user_id(client_id: uuid.UUID, user_id: uuid.UUID) -> PrincipalUserInDBSchema:
        from src.types.user_types import PrincipalUserTypes

        return PrincipalUserInDBSchema(
            client_id=client_id,
            user_id=user_id,
            email="foo.bar@example.com",
            username="foo.bar",
            preferred_name="Mr. Foo Bar",
            org_name="Example Inc",
            user_type=PrincipalUserTypes.PRINCIPAL_USER_ADMIN,
            hashed_password='$2b$12$cQXJ/inXvNuXyjzenYEA/..TZbhTEkIxTLwkwEywWRjifQG6T.xMK', # brcypt hash of hello
        )
    
    @staticmethod
    def get_scopes_granted_by_user_to_client(user_id, user_client_id, client_id):
        return set(OIDCScopes.__members__.keys())
    

        
