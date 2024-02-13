from fastapi import APIRouter

from .credentials import router as credentials_router
from .users       import router as pua_router
from .register    import router as registration_router
from .unregister  import router as unregistration_router

router = APIRouter()

router.include_router(credentials_router)
router.include_router(pua_router)
router.include_router(registration_router)
router.include_router(unregistration_router)
