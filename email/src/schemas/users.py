from pydantic import BaseModel
from pydantic import EmailStr, HttpUrl


class DraftUserSchema(BaseModel):
    email: EmailStr
    verification_link: HttpUrl



