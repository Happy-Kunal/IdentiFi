from enum import Enum

class PrincipalUserTypes(str, Enum):
    PRINCIPAL_USER_ADMIN = "PRINCIPAL_USER_ADMIN"
    PRINCIPAL_USER_CLIENT = "PRINCIPAL_USER_CLIENT"
    
class ServiceProviderTypes(str, Enum):
    SERVICE_PROVIDER = "SERVICE_PROVIDER"

