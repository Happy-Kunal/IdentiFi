from enum import Enum


class UserType(str, Enum):
    ADMIN_USER = "ADMIN_USER"
    WORKER_USER = "WORKER_USER"
    SERVICE_PROVIDER = "SERVICE_PROVIDER"

    def is_principal_user(self):
        return self.value in (UserType.ADMIN_USER, UserType.WORKER_USER)
    
    def is_service_provider(self):
        return self.value is UserType.SERVICE_PROVIDER


