from .service_provider_model import ServiceProviderByClientID, ServiceProviderByUsername
from .users import UserByEmail, AdminUserByEmail, WorkerUserByEmail
from .users import UserByUserID, AdminUserByUserID, WorkerUserByUserID
from .users import UserByUsername, AdminUserByUsername, WorkerUserByUsername
from .users import UserDraft, AdminUserDraft, WorkerUserDraft

models_to_be_synced = [
    ServiceProviderByClientID,
    ServiceProviderByUsername,
    UserByEmail,
    UserByUserID,
    UserByUsername,
    UserDraft,
]
