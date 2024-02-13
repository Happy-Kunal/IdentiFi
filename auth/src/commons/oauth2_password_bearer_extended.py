from typing import Dict
from typing_extensions import Annotated, Doc
from fastapi import Request
from fastapi.security import OAuth2PasswordBearer

class OAuth2PasswordBearerExtended(OAuth2PasswordBearer):
    """
    similar as fastapi.security.OAuth2PasswordBearer
    if `Authorization` header isn't set it or not of type `bearer`
    it extracts access_token from cookie.
    """
    def __init__(
        self,
        tokenUrl: str,
        scheme_name: str | None = None,
        scopes: dict[str, str] | None = None,
        description: str | None = None,
        auto_error: bool = True,
        cookie_name: str = "access_token"
    ):
        super().__init__(tokenUrl, scheme_name, scopes, description, auto_error)
        self.cookie_name = cookie_name

    async def __call__(self, request: Request) -> str | None:
        
        try:
            token = await super().__call__(request)
        except:
            token = request.cookies.get(self.cookie_name)
            if (not token):
                raise # reraise the exception

        return token

