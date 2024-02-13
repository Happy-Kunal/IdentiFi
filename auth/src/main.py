from typing import Union, Annotated

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles

from src.api_crud import router as api_crud_router
from src.oidc import router as oidc_router
from src.schemas import UserOutputSchema, ServiceProviderOutputSchema
from src.security import get_current_user
from src.security import router as security_router

app = FastAPI()

app.include_router(security_router)
app.include_router(oidc_router)
app.include_router(api_crud_router)

@app.get("/health")
async def hello():
    return {"status": "good"}

@app.get("/me", response_model=Union[UserOutputSchema, ServiceProviderOutputSchema])
async def get_curr_user(user: Annotated[UserOutputSchema | ServiceProviderOutputSchema, Depends(get_current_user)]):
    return user

app.mount("/", StaticFiles(directory="src/static", html=True), name="static")
