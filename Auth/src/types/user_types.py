from enum import Enum

class UserType(str, Enum):
    PRINCIPAL_USER = "PRINCIPAL_USER"
    SERVICE_PROVIDER = "SERVICE_PROVIDER"
    OIDC_CLIENT = "OIDC_CLIENT"

    def __eq__(self, other: object) -> bool:
        return (
            (super().__eq__(other))
            or (self.value == UserType.PRINCIPAL_USER.value and isinstance(other, PrincipalUserTypes))
            or (self.value == UserType.SERVICE_PROVIDER.value and isinstance(other, ServiceProviderTypes))
        )

class PrincipalUserTypes(str, Enum):
    PRINCIPAL_USER_ADMIN = "PRINCIPAL_USER_ADMIN"
    PRINCIPAL_USER_WORKER = "PRINCIPAL_USER_WORKER"

    def __eq__(self, other: object) -> bool:
        return (
            (super().__eq__(other))
            or (isinstance(other, UserType) and other.value == UserType.PRINCIPAL_USER)
        )
    
class ServiceProviderTypes(str, Enum):
    SERVICE_PROVIDER = "SERVICE_PROVIDER"

    def __eq__(self, other: object) -> bool:
        return (
            (super().__eq__(other))
            or isinstance(other, UserType) and other.value == UserType.SERVICE_PROVIDER
        )

