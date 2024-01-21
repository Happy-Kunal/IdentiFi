from typing import Union

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles
from typing_extensions import Annotated

from src.oidc import router as oidc_router
from src.schemas import PrincipalUserOutputSchema, ServiceProviderOutputSchema
from src.security import get_current_user
from src.security import router as security_router

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