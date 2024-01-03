import uuid

from pydantic import BaseModel
from pydantic import EmailStr

class PrincipalUserBaseSchema(BaseModel):
    org_id: uuid.UUID
    user_id: uuid.UUID
    email: EmailStr
    username: str
    preferred_name: str
    org_name: str

class PrincipalUserInputSchema(PrincipalUserBaseSchema):
    password: str

class PrincipalUserInDBSchema(PrincipalUserBaseSchema):
    hashed_password: str

class PrincipalUserOutputSchema(PrincipalUserBaseSchema):
    pass
