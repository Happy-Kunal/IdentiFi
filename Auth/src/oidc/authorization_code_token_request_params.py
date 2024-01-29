from typing import Annotated
from typing_extensions import Doc
from uuid import UUID

from fastapi import Depends, Form, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, HttpUrl



http_basic_auth_scheme = HTTPBasic()


class AuthorizationCodeTokenRequestParamsSchema(BaseModel):
    grant_type: str
    code: str
    redirect_uri: HttpUrl
    client_id: UUID
    client_secret: str


class __AuthorizationCodeTokenRequest:
   """
   It supports extracting `Token Request` Params from `Request` for
   authorization_code flow.

   It supports client_secret_basic, client_secret_post as per (OIDC specs)
   [https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication]
   for extracting Client Credentials for Client Authentication from `Request`.
   """
   
   async def __call__(
        self,
        *,
        request: Request,
        grant_type: Annotated[
            str,
            Form(pattern="authorization_code"),
            Doc(
                """
                REQUIRED.  Value MUST be set to "authorization_code".
                """
            )
        ] = "authorization_code",
        code: Annotated[
            str,
            Form(),
            Doc(
                """
                REQUIRED.  The authorization code received from the
                authorization server.
                """
            )
        ],
        redirect_uri: Annotated[
            HttpUrl | None,
            Form(),
            Doc(
                """
                REQUIRED, if the "redirect_uri" parameter was included in the
                authorization request as described in
                [Section 4.1.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1),
                and their values MUST be identical
                """
            )
        ] = None,
        client_id: Annotated[
            UUID | None,
            Form(),
            Doc(
                """
                REQUIRED, if the client is not authenticating with the
                authorization server as described in
                [Section 3.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1).
                
                if passed in HTTP request entity-body (application/x-www-form-urlencoded)
                and also in Authorization header (HTTP Basic Auth) value in body takes
                precedence.
                """
            )
        ] = None,
        client_secret: Annotated[
            str | None,
            Form(),
            Doc(
                """
                REQUIRED, if the client is not authenticating with the
                authorization server as described in
                [Section 3.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1).

                and if using client_secret_post as per
                https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
                to authenticate the client.


                if passed in HTTP request entity-body (application/x-www-form-urlencoded)
                and also in Authorization header (HTTP Basic Auth) value in body takes
                precedence.
                """
            )
        ] = None,
    ) -> AuthorizationCodeTokenRequestParamsSchema:
        self.grant_type = grant_type
        self.code = code
        self.redirect_uri = redirect_uri
        
        if (not (client_id and client_secret)):
            try:
                http_basic_auth_params: HTTPBasicCredentials = await http_basic_auth_scheme(request=request)
                client_id = client_id or UUID(http_basic_auth_params.username)
                client_secret = client_secret or http_basic_auth_params.password
            except HTTPException:
                raise # This will re-raise the last thrown exception, with original stack trace intact
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="client_id passed in Authorization header is not of type UUID",
                    headers={"WWW-Authenticate": "Basic"}
                )
        
        return AuthorizationCodeTokenRequestParamsSchema(
            grant_type=grant_type,
            code=code,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret
        )

AuthorizationCodeTokenRequest = __AuthorizationCodeTokenRequest()

AuthorizationCodeTokenRequestParams = Annotated[AuthorizationCodeTokenRequestParamsSchema, Depends(AuthorizationCodeTokenRequest)]

# example
if __name__ == "__main__":
    from fastapi import FastAPI

    app = FastAPI()


    @app.post("/token")
    async def fake_token(params: AuthorizationCodeTokenRequestParams):
        return {
            "grant_type": params.grant_type,
            "code": params.code,
            "redirect_uri": params.redirect_uri,
            "client_id": params.client_id,
            "client_secret": params.client_secret,
        }
