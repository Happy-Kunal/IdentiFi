from enum import Enum


class Scopes(str, Enum):
    """
    these scopes are used by authorization server to identify
    user type on our website/domain name.
    """

    admin = "principal-user:admin"
    worker = "principal-user:worker"
    service_provider = "service-provider:all"


class OIDCScopes(str, Enum):
    """
    these scopes are granted to third-party website (service provider)
    using our authorization server as An identity provider (IdP).
    """
    openid = "openid"
    profile = "profile"                                 # username, preferred_name, user_id
    email = "email"                                     # org_name, email
    service_provider_config = "service-provider-config" # service-provider-config set by admin of principal-user (if any)
