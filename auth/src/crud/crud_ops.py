from uuid import UUID, uuid4

from cassandra.auth import PlainTextAuthProvider
from cassandra.cluster import Cluster, Session
from cassandra.cqlengine import connection, models
from cassandra.cqlengine.query import BatchQuery
from cassandra.io.libevreactor import LibevConnection
from cassandra.policies import ExponentialReconnectionPolicy

from src.commons import get_password_hash, make_secret
from src.config import AstraCassandra, cfg
from src.schemas import (ServiceProviderInDBSchema, ServiceProviderInputSchema,
                         UserInDBSchema, UserInputSchema)
from src.types import UserType
from src.types.scopes import OIDCScopes

from .exceptions import (DatabaseConnectionAlreadyExists,
                         NoDatabaseConnectionExists)
from .models import ServiceProviderByClientID, ServiceProviderByUsername
from .models.users import (AdminUserByEmail, AdminUserByUserID,
                           AdminUserByUsername, AdminUserDraft, UserByEmail,
                           UserByUserID, UserByUsername, UserDraft,
                           WorkerUserByEmail, WorkerUserByUserID,
                           WorkerUserByUsername, WorkerUserDraft)


class CRUDOps:
    __cluster: Cluster | None = None
    __session: Session | None = None
    __default_connection_name: str = "identifi_auth_connection"

    @classmethod
    def connect(cls):
        """
        make connection to database
        """
        if (cls.__cluster is not None or cls.__session is not None):
            raise DatabaseConnectionAlreadyExists
        elif isinstance(cfg.db.cassandra, AstraCassandra):
            cloud_config = {"secure_connect_bundle": str(cfg.db.cassandra.secure_connection_bundle.absolute())}

            cls.__cluster = Cluster(
                auth_provider=PlainTextAuthProvider(
                    cfg.db.cassandra.client_id, cfg.db.cassandra.client_secret
                ),
                cloud=cloud_config,
                connection_class=LibevConnection,
                reconnection_policy=ExponentialReconnectionPolicy(base_delay=0.5, max_delay=10)
            )
        else:
            cls.__cluster = Cluster(
                cfg.db.cassandra.hosts,
                protocol_version=cfg.db.cassandra.protocol_version,
                connection_class=LibevConnection,
                reconnection_policy=ExponentialReconnectionPolicy(base_delay=0.5, max_delay=60)
            )

        cls.__session = cls.__cluster.connect(keyspace=cfg.db.cassandra.keyspace)

        connection.register_connection(name=cls.__default_connection_name, session=cls.__session, default=True)
        models.DEFAULT_KEYSPACE = cfg.db.cassandra.keyspace

    @classmethod
    def ping_db(cls) -> bool:
        """
        executes a simple select query on database once returns `True` if query succeed else `False`
        """
        row = cls.__session.execute("select release_version from system.local").one()
        return bool(row)

    
    @classmethod
    def disconnect(cls):
        if (cls.__cluster is None or cls.__session is None):
            raise NoDatabaseConnectionExists
        
        connection.unregister_connection(cls.__default_connection_name)
        cls.__session.shutdown()
        cls.__cluster.shutdown()




    @classmethod
    def get_user_by_username(cls, org_identifier: str, username: str) -> UserInDBSchema:
        return UserInDBSchema.model_validate(
            UserByUsername.filter(
                org_identifier=org_identifier,
                username=username
            ).get()
        )
    
    @classmethod
    def get_service_provider_by_username(cls, username: str) -> ServiceProviderInDBSchema:
        return ServiceProviderInDBSchema.model_validate(
            ServiceProviderByUsername.filter(username=username).first()
        )
    
    @classmethod
    def get_service_provider_by_client_id(cls, client_id: UUID) -> ServiceProviderInDBSchema:
        return ServiceProviderInDBSchema.model_validate(
            ServiceProviderByClientID.filter(client_id=client_id).first()
        )
    
    @classmethod
    def get_user_by_user_id(cls, org_identifier: str, user_id: UUID) -> UserInDBSchema:
        return UserInDBSchema.model_validate(
            UserByUserID.filter(
                org_identifier=org_identifier,
                user_id=user_id
            ).get()
        )
    
    @classmethod
    def get_scopes_granted_by_user_to_client(cls, org_identifier: str, user_id: UUID, client_id: UUID) -> set[OIDCScopes]:
        # TODO: implement in future
        return set(OIDCScopes.__members__.values())
    
    @classmethod
    def create_user(cls, user: UserInputSchema) -> UserInDBSchema:
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
    
    @classmethod
    def create_service_provider(cls, service_provider: ServiceProviderInputSchema) -> ServiceProviderInDBSchema:
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
    
    @classmethod
    def delete_user(cls, org_identifier: str, user_id: UUID) -> UserInDBSchema:
        user = CRUDOps.get_user_by_user_id(org_identifier=org_identifier, user_id=user_id)

        with BatchQuery() as b:
            UserByEmail.filter(org_identifier=org_identifier, email=user.email).batch(b).delete()
            UserByUserID.filter(org_identifier=org_identifier, user_id=user.user_id).batch(b).delete()
            UserByUsername.filter(org_identifier=org_identifier, username=user.username).batch(b).delete()
        
        return user
    
    @classmethod
    def delete_service_provider(cls, username: str) -> ServiceProviderInDBSchema:
        service_provider = CRUDOps.get_service_provider_by_username(username=username)

        with BatchQuery() as b:
            ServiceProviderByClientID.filter(client_id=service_provider.client_id).batch(b).delete()
            ServiceProviderByUsername.filter(username=service_provider.username).batch(b).delete()

        return service_provider
    
    
    
    @classmethod
    def reset_service_provider_secret(cls, username: str) -> ServiceProviderInDBSchema:
        service_provider = CRUDOps.get_service_provider_by_username(username=username)

        new_secret = make_secret()

        with BatchQuery() as b:
            ServiceProviderByClientID.filter(client_id=service_provider.client_id).batch(b).update(client_secret=new_secret)
            ServiceProviderByUsername.filter(username=service_provider.username).batch(b).update(client_secret=new_secret)

        service_provider.client_secret = new_secret
        return service_provider
    
    
    @classmethod
    def create_user_draft(cls, draft_user: UserInputSchema) -> UserInDBSchema:
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
    
    @classmethod
    def get_all_users_by_org_identifier(cls, org_identifier: str, limit: int = 1000, offset: int = 0) -> list[UserInDBSchema]:
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

    @classmethod
    def get_users_with_username_starts_with(cls, org_identifier: str, q: str, limit: int = 25, offset: int = 0) -> list[UserInDBSchema]:
        return [
            UserInDBSchema.model_validate(user)
            for user in UserByUsername
                .filter(org_identifier=org_identifier)
                .filter(username__gte=q, username__lt=chr(ord(q[0]) + 1))
                .limit(limit + offset)[offset:]
        ]
    
    @classmethod
    def get_users_with_email_starts_with(cls, org_identifier: str, q: str, limit: int = 25, offset: int = 0) -> list[UserInDBSchema]:
        return [
            UserInDBSchema.model_validate(user)
            for user in UserByEmail
                .filter(org_identifier=org_identifier)
                .filter(email__gte=q, email__lt=chr(ord(q[0]) + 1))
                .limit(limit + offset)[offset:]
        ]
    
    
    @classmethod
    def promote_user_to_admin(cls, org_identifier: str, user_id: UUID) -> UserInDBSchema:
        user = CRUDOps.get_user_by_user_id(org_identifier=org_identifier, user_id=user_id)

        with BatchQuery() as b:
            UserByEmail.filter(org_identifier=org_identifier, email=user.email).batch(b).update(user_type=UserType.ADMIN_USER.value)
            UserByUserID.filter(org_identifier=org_identifier, user_id=user.user_id).batch(b).update(user_type=UserType.ADMIN_USER.value)
            UserByUsername.filter(org_identifier=org_identifier, username=user.username).batch(b).update(user_type=UserType.ADMIN_USER.value)

        user.user_type = UserType.ADMIN_USER
        return user
        
    
    @classmethod
    def demote_user_to_worker(cls, org_identifier: str, user_id: UUID) -> UserInDBSchema:
        user = CRUDOps.get_user_by_user_id(org_identifier=org_identifier, user_id=user_id)

        with BatchQuery() as b:
            UserByEmail.filter(org_identifier=org_identifier, email=user.email).batch(b).update(user_type=UserType.WORKER_USER.value)
            UserByUserID.filter(org_identifier=org_identifier, user_id=user.user_id).batch(b).update(user_type=UserType.WORKER_USER.value)
            UserByUsername.filter(org_identifier=org_identifier, username=user.username).batch(b).update(user_type=UserType.WORKER_USER.value)

        user.user_type = UserType.WORKER_USER
        return user
        
    
    
    
