from typing import Union
from typing_extensions import Annotated

from fastapi import FastAPI
from fastapi import Depends
from fastapi.staticfiles import StaticFiles

from src.security.security import router as security_router
from src.security.utils import get_current_user

from src.schemas.principal_user import PrincipalUserOutputSchema
from src.schemas.service_provider import ServiceProviderOutputSchema

from src.oidc.oidc_authorization_code_flow import router as oidc_router

app = FastAPI()

app.include_router(security_router)
app.include_router(oidc_router)

@app.get("/hello")
async def hello():
    return {"hello": "world"}

@app.get("/me", response_model=Union[PrincipalUserOutputSchema, ServiceProviderOutputSchema])
async def get_curr_user(user: Annotated[dict, Depends(get_current_user)]):
    return user

app.mount("/", StaticFiles(directory="src/static", html=True), name="static")