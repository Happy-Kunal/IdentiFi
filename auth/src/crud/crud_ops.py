from uuid import uuid4, UUID

from src.config import cfg
from src.models import PrincipalUserModel, ServiceProviderModel
from src.schemas import PrincipalUserInDBSchema, ServiceProviderInDBSchema
from src.types import PrincipalUserTypes
from src.types.scopes import OIDCScopes

from .syncer import CassandraSyncer


CASSANDRA_HOSTS = cfg.db.cassandra.hosts
CASSANDRA_KEYSPACE = cfg.db.cassandra.keyspace
CASSANDRA_PROTOCOL_VERSION = cfg.db.cassandra.protocol_version

UPDATE_DB_SCHEMA = cfg.db.schemas.update

models = [
    PrincipalUserModel,
    ServiceProviderModel,
]

if UPDATE_DB_SCHEMA:
    syncer = CassandraSyncer()
    syncer.sync(models=models)

class CRUDOps:
    # TODO: replace dummy implementation with actual one
    @staticmethod
    def get_prinicipal_user_by_username(client_id: UUID, username: str):
        data = {
            "client_id"       : client_id,
            "user_id"         : uuid4(),
            "email"           : f"{username.replace(' ', '.')}@example.com",
            "username"        : username,
            "preferred_name"  : f"{username}",
            "org_name"        : "example.com",
            "hashed_password" : '$2b$12$cQXJ/inXvNuXyjzenYEA/..TZbhTEkIxTLwkwEywWRjifQG6T.xMK', # brcypt hash of hello
            "user_type"       : PrincipalUserTypes.PRINCIPAL_USER_ADMIN
        }

        return PrincipalUserInDBSchema(**data)
    
    @staticmethod
    def get_service_provider_by_username(client_id: UUID, username: str):
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
    def get_principal_user_by_user_id(client_id: UUID, user_id: UUID) -> PrincipalUserInDBSchema:
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
    def get_scopes_granted_by_user_to_client(user_id, user_client_id, client_id) -> set[OIDCScopes]:
        return set([scope.value for scope in OIDCScopes.__members__.values()])
    
    @staticmethod
    def get_principal_user_client_id_by_org_username(org_username: str):
        return uuid4()
    
    @staticmethod
    def create_principal_user_admin(admin: PrincipalUserInDBSchema, org_identifier: str) -> PrincipalUserInDBSchema:
        # create batch
        # add org_identifier => client_id mapping to db
        # add admin to db

        return admin
    
    @staticmethod
    def create_service_provider(service_provider: ServiceProviderInDBSchema):
        return service_provider
    
    @staticmethod
    def delete_principal_user(user: PrincipalUserInDBSchema, force=False) -> PrincipalUserInDBSchema:
        # if no `user`` left in org of user:
        #     delete org_identifier => client_id mapping in db
        # delete user from org
        
        return user
    
    @staticmethod
    def delete_service_provider(service_provider: ServiceProviderInDBSchema) -> ServiceProviderInDBSchema:
        return service_provider
    
    @staticmethod
    def reset_service_provider_secret(service_provider: ServiceProviderInDBSchema) -> ServiceProviderInDBSchema:
        return service_provider
    
    @staticmethod
    def create_principal_user_worker_draft(draft_worker: PrincipalUserInDBSchema) -> PrincipalUserInDBSchema:
        return draft_worker
    
    @staticmethod
    def get_users_in_principal_user_org(org_id: UUID, limit: int = 25, offset: int = 0) -> list[PrincipalUserInDBSchema]:
        return []
    
    @staticmethod
    def get_principal_users_with_username_like(client_id: UUID, q: str, limit: int = 25, offset: int = 0) -> list[PrincipalUserInDBSchema]:
        return []
    
    @staticmethod
    def get_principal_users_with_email_like(client_id: UUID, q: str, limit: int = 25, offset: int = 0) -> list[PrincipalUserInDBSchema]:
        return []
    
    @staticmethod
    def promote_principal_user_worker(client_id: UUID, worker_id: UUID) -> PrincipalUserInDBSchema:
        return PrincipalUserInDBSchema(
            client_id=client_id,
            user_id=worker_id,
            email="foo.bar@example.com",
            username="foo.bar",
            preferred_name="Mr. Foo Bar",
            org_name="Example Inc",
            user_type=PrincipalUserTypes.PRINCIPAL_USER_ADMIN,
            hashed_password='$2b$12$cQXJ/inXvNuXyjzenYEA/..TZbhTEkIxTLwkwEywWRjifQG6T.xMK', # brcypt hash of hello
        )
    
    @staticmethod
    def demote_principal_user_admin(client_id: UUID, admin_id: UUID) -> PrincipalUserInDBSchema:
        return PrincipalUserInDBSchema(
            client_id=client_id,
            user_id=admin_id,
            email="foo.bar@example.com",
            username="foo.bar",
            preferred_name="Mr. Foo Bar",
            org_name="Example Inc",
            user_type=PrincipalUserTypes.PRINCIPAL_USER_WORKER,
            hashed_password='$2b$12$cQXJ/inXvNuXyjzenYEA/..TZbhTEkIxTLwkwEywWRjifQG6T.xMK', # brcypt hash of hello
        )

    
    
    
