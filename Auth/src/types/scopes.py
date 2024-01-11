from enum import Enum

class Scopes(str, Enum):
    """
    these scopes are used by authorization server to identify
    user type on our website/domain name.
    """

    admin = "principal-user:admin"
    worker = "principal-user:worker"
    service_provider = "service-provider:all"
