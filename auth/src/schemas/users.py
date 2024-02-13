from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field
from pydantic import ConfigDict
from pydantic import field_serializer
from pydantic import EmailStr

from src.types import UserType


class UserBaseSchema(BaseModel):
    org_identifier: str = Field(min_length=6, max_length=255, pattern=r"^\S+$")
    username      : str = Field(min_length=6, max_length=255, pattern=r"^\S+$")
    user_id       : UUID
    email         : EmailStr
    name          : str = Field(min_length=6, max_length=255)
    user_type     : UserType

    @field_serializer("user_id")
    def serialize_user_id(self, user_id: UUID, _info):
        return str(user_id)

    @field_serializer("user_type")
    def serialize_user_type(self, user_type: UserType, _info):
        return user_type.value
    
    
    

class UserInputSchema(UserBaseSchema):
    user_id : UUID = Field(default_factory=uuid4)
    password: str = Field(min_length=8, max_length=255) # TODO: strong password check


class UserInDBSchema(UserBaseSchema):
    model_config = ConfigDict(from_attributes=True)
    
    hashed_password: str



class UserOutputSchema(UserBaseSchema):
    model_config = ConfigDict(from_attributes=True)

