from typing import List, Callable

from fastapi import status, HTTPException

from src.types.scopes import Scopes


invalid_token_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Incorrect username or password or client_id",
    headers={"WWW-Authenticate": "Bearer"},
)

invalid_scopes_selection_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid Combination of Scopes",
    headers={"WWW-Authenticate": "Bearer"},
)

not_enough_permission_exception: Callable[[List[Scopes]], HTTPException] = lambda scopes: HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not enough permissions",
    headers={
        "WWW-Authenticate": f'Bearer scopes="{" ".join(scopes)}"' if (scopes) else "Bearer"
    },
)
