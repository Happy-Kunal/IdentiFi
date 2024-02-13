from uuid import uuid4, UUID

from cassandra.cqlengine.query import BatchQuery
from cassandra.cqlengine import connection

from src.config import cfg
from src.schemas import UserInDBSchema, UserInputSchema, ServiceProviderInDBSchema, ServiceProviderInputSchema
from src.types import UserType
from src.types.scopes import OIDCScopes

from src.commons import get_password_hash, make_secret

from .models import ServiceProviderByClientID, ServiceProviderByUsername
from .models.users import UserByUsername, UserByEmail, UserByUserID, UserDraft, AdminUserByEmail, WorkerUserByEmail, AdminUserByUsername, WorkerUserByUsername, AdminUserByUserID, WorkerUserByUserID, AdminUserDraft, WorkerUserDraft
from .syncer import CassandraSyncer


CASSANDRA_HOSTS = cfg.db.cassandra.hosts
CASSANDRA_KEYSPACE = cfg.db.cassandra.keyspace
CASSANDRA_PROTOCOL_VERSION = cfg.db.cassandra.protocol_version

UPDATE_DB_SCHEMA = cfg.db.schemas.update

models = [
    ServiceProviderByClientID,
    ServiceProviderByUsername,
    UserByEmail,
    UserByUserID,
    UserByUsername,
    UserDraft,
]

connection.setup(CASSANDRA_HOSTS, CASSANDRA_KEYSPACE, retry_connect=True)

if UPDATE_DB_SCHEMA:
    syncer = CassandraSyncer(session=connection.get_session())
    syncer.sync(models=models)

class CRUDOps:
    @staticmethod
    def get_user_by_username(org_identifier: str, username: str) -> UserInDBSchema:
        return UserInDBSchema.model_validate(
            UserByUsername.filter(
                org_identifier=org_identifier,
                username=username
            ).get()
        )
    
    @staticmethod
    def get_service_provider_by_username(username: str) -> ServiceProviderInDBSchema:
        return ServiceProviderInDBSchema.model_validate(
            ServiceProviderByUsername.filter(username=username).first()
        )
    
    @staticmethod
    def get_service_provider_by_client_id(client_id: UUID) -> ServiceProviderInDBSchema:
        return ServiceProviderInDBSchema.model_validate(
            ServiceProviderByClientID.filter(client_id=client_id).first()
        )
    
    @staticmethod
    def get_user_by_user_id(org_identifier: str, user_id: UUID) -> UserInDBSchema:
        return UserInDBSchema.model_validate(
            UserByUserID.filter(
                org_identifier=org_identifier,
                user_id=user_id
            ).get()
        )
    
    @staticmethod
    def get_scopes_granted_by_user_to_client(org_identifier: str, user_id: UUID, client_id: UUID) -> set[OIDCScopes]:
        # TODO: implement in future
        return set(OIDCScopes.__members__.values())
    
    @staticmethod
    def create_user(user: UserInputSchema) -> UserInDBSchema:
        user_in_db = UserInDBSchema(
            org_identifier=user.org_identifier,
            username=user.username,
            user_id=user.user_id,
            email=user.email,
            name=user.name,
            user_type=user.user_type,
            hashed_password=get_password_hash(user.password)
        )

        user_in_db_data = user_in_db.model_dump()

        with BatchQuery() as b:
            if (user_in_db.user_type is UserType.ADMIN_USER):
                AdminUserByEmail.batch(b).create(**user_in_db_data)
                AdminUserByUserID.batch(b).create(**user_in_db_data)
                AdminUserByUsername.batch(b).create(**user_in_db_data)
            else:
                WorkerUserByEmail.batch(b).create(**user_in_db_data)
                WorkerUserByUserID.batch(b).create(**user_in_db_data)
                WorkerUserByUsername.batch(b).create(**user_in_db_data)
        
        return user_in_db
    
    @staticmethod
    def create_service_provider(service_provider: ServiceProviderInputSchema) -> ServiceProviderInDBSchema:
        # TODO: convert to lwt transaction
        service_provider_in_db = ServiceProviderInDBSchema(
            username=service_provider.username,
            email=service_provider.email,
            client_id=uuid4(),
            client_secret=make_secret(),
            hashed_password=get_password_hash(service_provider.password)
        )
        service_provider_in_db_data = service_provider_in_db.model_dump()

        with BatchQuery() as b:
            ServiceProviderByClientID.batch(b).create(**service_provider_in_db_data)
            ServiceProviderByUsername.batch(b).create(**service_provider_in_db_data)

        return service_provider_in_db
    
    @staticmethod
    def delete_user(org_identifier: str, user_id: UUID) -> UserInDBSchema:
        user = CRUDOps.get_user_by_user_id(org_identifier=org_identifier, user_id=user_id)

        with BatchQuery() as b:
            UserByEmail.filter(org_identifier=org_identifier, email=user.email).batch(b).delete()
            UserByUserID.filter(org_identifier=org_identifier, user_id=user.user_id).batch(b).delete()
            UserByUsername.filter(org_identifier=org_identifier, username=user.username).batch(b).delete()
        
        return user
    
    @staticmethod
    def delete_service_provider(username: str) -> ServiceProviderInDBSchema:
        service_provider = CRUDOps.get_service_provider_by_username(username=username)

        with BatchQuery() as b:
            ServiceProviderByClientID.filter(client_id=service_provider.client_id).batch(b).delete()
            ServiceProviderByUsername.filter(username=service_provider.username).batch(b).delete()

        return service_provider
    
    
    
    @staticmethod
    def reset_service_provider_secret(username: str) -> ServiceProviderInDBSchema:
        service_provider = CRUDOps.get_service_provider_by_username(username=username)

        new_secret = make_secret()

        with BatchQuery() as b:
            ServiceProviderByClientID.filter(client_id=service_provider.client_id).batch(b).update(client_secret=new_secret)
            ServiceProviderByUsername.filter(username=service_provider.username).batch(b).update(client_secret=new_secret)

        service_provider.client_secret = new_secret
        return service_provider
    
    
    @staticmethod
    def create_user_draft(draft_user: UserInputSchema) -> UserInDBSchema:
        draft_user_in_db = UserInDBSchema(
            org_identifier=draft_user.org_identifier,
            username=draft_user.username,
            user_id=draft_user.user_id,
            email=draft_user.email,
            name=draft_user.email,
            user_type=draft_user.user_type,
            hashed_password=get_password_hash(draft_user.password)
        )
        
        if (draft_user_in_db.user_type is UserType.ADMIN_USER):
            AdminUserDraft.create(**draft_user_in_db.model_dump())
        else:
            WorkerUserDraft.create(**draft_user_in_db.model_dump())
        
        return draft_user_in_db
    
    @staticmethod
    def get_all_users_by_org_identifier(org_identifier: str, limit: int = 1000, offset: int = 0) -> list[UserInDBSchema]:
        """
        since cassandra doesn't support offset natively.
        **this query is costly**. so it is RECOMMENDED to
        query significant chunk of data and caching data
        on user-side for better performance.
        """
        # TODO: implement mechanism for caching page information on client side as well

        return [
            UserInDBSchema.model_validate(user)
            for user in UserByUsername
                .filter(org_identifier=org_identifier)
                .limit(offset + limit)[offset:]
        ]

    @staticmethod
    def get_users_with_username_like(org_identifier: str, q: str, limit: int = 25, offset: int = 0) -> list[UserInDBSchema]:
        return [
            UserInDBSchema.model_validate(user)
            for user in UserByUsername
                .filter(org_identifier=org_identifier)
                .filter(username__like=f"%{q}%")
                .limit(limit + offset)[offset:]
        ]
    
    @staticmethod
    def get_users_with_email_like(org_identifier: str, q: str, limit: int = 25, offset: int = 0) -> list[UserInDBSchema]:
        return [
            UserInDBSchema.model_validate(user)
            for user in UserByEmail
                .filter(org_identifier=org_identifier)
                .filter(email__like=f"%{q}%")
                .limit(limit + offset)[offset:]
        ]
    
    
    @staticmethod
    def promote_user_to_admin(org_identifier: str, user_id: UUID) -> UserInDBSchema:
        user = CRUDOps.get_user_by_user_id(org_identifier=org_identifier, user_id=user_id)

        with BatchQuery() as b:
            UserByEmail.filter(org_identifier=org_identifier, email=user.email).batch(b).update(user_type=UserType.ADMIN_USER.value)
            UserByUserID.filter(org_identifier=org_identifier, user_id=user.user_id).batch(b).update(user_type=UserType.ADMIN_USER.value)
            UserByUsername.filter(org_identifier=org_identifier, username=user.username).batch(b).update(user_type=UserType.ADMIN_USER.value)

        user.user_type = UserType.ADMIN_USER
        return user
        
    
    @staticmethod
    def demote_user_to_worker(org_identifier: str, user_id: UUID) -> UserInDBSchema:
        user = CRUDOps.get_user_by_user_id(org_identifier=org_identifier, user_id=user_id)

        with BatchQuery() as b:
            UserByEmail.filter(org_identifier=org_identifier, email=user.email).batch(b).update(user_type=UserType.WORKER_USER.value)
            UserByUserID.filter(org_identifier=org_identifier, user_id=user.user_id).batch(b).update(user_type=UserType.WORKER_USER.value)
            UserByUsername.filter(org_identifier=org_identifier, username=user.username).batch(b).update(user_type=UserType.WORKER_USER.value)

        user.user_type = UserType.WORKER_USER
        return user
        
    
    
    
