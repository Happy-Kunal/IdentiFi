from typing import Union
from uuid import UUID

from fastapi import Form, Query
from pydantic import HttpUrl

from typing_extensions import Annotated, Doc


class OAuth2AuthorizationCodeRequestForm:
    """
    This is a dependency class to collect the `client_id`, `redirect_uri` and `state` as form data
    for an OAuth2 Authorization flow.

    The OAuth2 specification dictates that for a Authorization flow the data should be
    collected using form data (instead of JSON) and that it should have the specific
    fields `client_id`, `redirect_uri` and `state`.

    All the initialization parameters are extracted from the request.

    Note that for OAuth2 the scope `items:read` is a single scope in an opaque string.
    You could have custom internal logic to separate it by colon caracters (`:`) or
    similar, and get the two parts `items` and `read`. Many applications do that to
    group and organize permisions, you could do it as well in your application, just
    know that that it is application specific, it's not part of the specification.
    """

    def __init__(
        self,
        *,
        grant_type: Annotated[
            str,
            Form(pattern="code"),
            Doc(
                """
                The OAuth2 spec says it is required and MUST be the fixed string
                "code".
                """
            ),
        ] = "code",
        client_id: Annotated[
            UUID,
            Form(),
            Doc(
                """
                `client_id` string. The OAuth2 spec requires the exact field name
                `username`.
                """
            ),
        ],
        redirect_uri: Annotated[
            HttpUrl,
            Form(),
            Doc(
                """
                `redirect_uri` string. The OAuth2 spec requires the exact field name
                `redirect_uri" it can be OPTIONAL if client already registered it with
                auth server but REQUIRED if not registered.
                """
            ),
        ],
        scope: Annotated[
            str,
            Form(),
            Doc(
                """
                A single string with actually several scopes separated by spaces. Each
                scope is also a string.

                For example, a single string with:

                ```python
                "items:read items:write users:read profile openid"
                ````

                would represent the scopes:

                * `items:read`
                * `items:write`
                * `users:read`
                * `profile`
                * `openid`
                """
            ),
        ] = "openid",
        state: Annotated[
            Union[str, None],
            Form(),
            Doc(
                """
                It is OAuth2 RECOMMENDED field.  An opaque value used by the
                client to maintain state between the request and callback.
                The authorization server includes this value when redirecting
                the user-agent back to the client.  The parameter SHOULD be
                used for preventing cross-site request forgery as described in
                [Section 10.12](https://datatracker.ietf.org/doc/html/rfc6749#section-10.12).
                """
            )
        ] = None
    ):
        
        self.grant_type = grant_type
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scopes = scope.split()
        self.state = state




class OAuth2AuthorizationCodeRequestQuery:
    """
    This is a dependency class to collect the `client_id`, `redirect_uri` and `state` as form data
    for an OAuth2 Authorization flow.

    The OAuth2 specification dictates that for a Authorization flow the data should be
    collected using form data (instead of JSON) and that it should have the specific
    fields `client_id`, `redirect_uri` and `state`.

    All the initialization parameters are extracted from the request.

    Note that for OAuth2 the scope `items:read` is a single scope in an opaque string.
    You could have custom internal logic to separate it by colon caracters (`:`) or
    similar, and get the two parts `items` and `read`. Many applications do that to
    group and organize permisions, you could do it as well in your application, just
    know that that it is application specific, it's not part of the specification.
    """

    def __init__(
        self,
        *,
        grant_type: Annotated[
            str,
            Query(pattern="code"),
            Doc(
                """
                The OAuth2 spec says it is required and MUST be the fixed string
                "code".
                """
            ),
        ] = "code",
        client_id: Annotated[
            UUID,
            Query(),
            Doc(
                """
                `client_id` string. The OAuth2 spec requires the exact field name
                `username`.
                """
            ),
        ],
        redirect_uri: Annotated[
            HttpUrl,
            Query(),
            Doc(
                """
                `redirect_uri` string. The OAuth2 spec requires the exact field name
                `redirect_uri" it can be OPTIONAL if client already registered it with
                auth server but REQUIRED if not registered.
                """
            ),
        ],
        scope: Annotated[
            str,
            Query(),
            Doc(
                """
                A single string with actually several scopes separated by spaces. Each
                scope is also a string.

                For example, a single string with:

                ```python
                "items:read items:write users:read profile openid"
                ````

                would represent the scopes:

                * `items:read`
                * `items:write`
                * `users:read`
                * `profile`
                * `openid`
                """
            ),
        ] = "openid",
        state: Annotated[
            Union[str, None],
            Query(),
            Doc(
                """
                It is OAuth2 RECOMMENDED field.  An opaque value used by the
                client to maintain state between the request and callback.
                The authorization server includes this value when redirecting
                the user-agent back to the client.  The parameter SHOULD be
                used for preventing cross-site request forgery as described in
                [Section 10.12](https://datatracker.ietf.org/doc/html/rfc6749#section-10.12).
                """
            )
        ] = None
    ):
        
        self.grant_type = grant_type
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scopes = scope.split()
        self.state = state

