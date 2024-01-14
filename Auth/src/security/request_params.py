# according to
# https://datatracker.ietf.org/doc/html/rfc6749#section-6
# we needed to be able to send refresh_token to "/token endpoint",
# which was also used by password flow,
# with grant_type=refresh_token inorder to obtain new access token
# but `fastapi.security.OAuth2PasswordRequestForm` doesn't support it
# so we needed to create something similar to
# `fastapi.security.OAuth2PasswordRequestForm` but that also support
# accepting refresh_token instead of other fields when grant_type=refresh_token


from typing_extensions import Annotated, Doc
from typing import Union


from fastapi import Cookie, Form
from fastapi import Request
from fastapi import status, HTTPException


class OAuth2PasswordOrRefreshTokenRequestParams:
    """
    This is a dependency class to collect the `username` and `password` as form data
    for an OAuth2 password flow. or refresh_token in case of using refresh token to
    obtain new access token according to OAuth2 Specs.

    The OAuth2 specification dictates that for a password flow the data should be
    collected using form data (instead of JSON) and that it should have the specific
    fields `username` and `password`.

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
        request: Request,
        grant_type: Annotated[
            str,
            Form(pattern="password|refresh_token"),
            Doc(
                """
                The OAuth2 spec says it is required and MUST be the fixed string
                "password". or it must be refresh_token when requesting for new
                access token using refresh_token as per 
                https://datatracker.ietf.org/doc/html/rfc6749#section-6 .
                """
            ),
        ],
        username: Annotated[
            Union[str, None],
            Form(),
            Doc(
                """
                `username` string. The OAuth2 spec requires the exact field name
                `username`. it will be ignored if grant_type=refresh_token
                """
            ),
        ] = None,
        password: Annotated[
            Union[str, None],
            Form(),
            Doc(
                """
                `password` string. The OAuth2 spec requires the exact field name
                `password". it will be ignored if grant_type=refresh_token
                """
            ),
        ] = None,
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

                it will be ignored if grant_type=refresh_token
                """
            ),
        ] = "",
        client_id: Annotated[
            Union[str, None],
            Form(),
            Doc(
                """
                If there's a `client_id`, it can be sent as part of the form fields.
                But the OAuth2 specification recommends sending the `client_id` and
                `client_secret` (if any) using HTTP Basic auth.
                """
            ),
        ] = None,
        client_secret: Annotated[
            Union[str, None],
            Form(),
            Doc(
                """
                If there's a `client_password` (and a `client_id`), they can be sent
                as part of the form fields. But the OAuth2 specification recommends
                sending the `client_id` and `client_secret` (if any) using HTTP Basic
                auth.
                """
            ),
        ] = None,
        refresh_token: Annotated[
            Union[str, None],
            Form(),
            Doc(
                """
                `refresh_token` string. The OAuth2 spec requires the exact field name
                `refresh_token` if grant_type=refresh_token.
                our implementation supports setting it through both `cookie` and `form`
                field but if both are present form will take precedence.

                it will be ignored if grant_type=password.
                """
            )
        ] = None
    ):
        
        self.grant_type = grant_type
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username if grant_type == "password" else None
        self.password = password if grant_type == "password" else None
        self.scopes = scope.split()
        self.refresh_token = (refresh_token or request.cookies.get("refresh_token")) if grant_type == "refresh_token" else None

        if (self.grant_type == "password" and (username == None or password == None)):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="either username or password or both missing for request with grant_type=password"
            )
        
        elif (self.grant_type == "refresh_token" and not refresh_token):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="refresh_token is missing for request with grant_type=refresh_token"
            )

