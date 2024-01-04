from enum import Enum

class Scopes(str, Enum):
    admin = "principal-user:admin"
    worker = "principal-user:worker"
    service_provider = "service-provider:all"
