from enum import Enum

class OIDCScopes(str, Enum):
    """
    these scopes are granted to third-party website (service provider)
    using our authorization server as An identity provider (IdP).
    """
    openid = "openid"
    profile = "profile"                                     # username, preferred_name, user_id
    email = "email"                         # org_name, email
    service_provider_config = "service-provider-config" # service-provider-config set by admin of principal-user (if any)
