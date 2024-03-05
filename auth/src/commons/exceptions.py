from fastapi import status, HTTPException

from src.types.scopes import Scopes


class InvalidTokenException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )

class CredentialsException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password or client_id (org_identifier)",
            headers={"WWW-Authenticate": "Bearer"}
        )

class InvalidScopesSelectionException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Combination of Scopes",
            headers={"WWW-Authenticate": "Bearer"}
        )

class NotEnoughPermissionException(HTTPException):
    def __init__(self, scopes: list[str] | None = None):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not enough permissions",
            headers={
                "WWW-Authenticate": f'Bearer scopes="{" ".join(scopes)}"' if (scopes) else "Bearer"
            },
        )
