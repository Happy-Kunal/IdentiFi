from fastapi import status, HTTPException

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
