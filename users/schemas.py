from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import date;

class UserSignUpSchema(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone_number: Optional[str]
    date_of_birth: Optional[str]
    address: Optional[str]
    gender: Optional[str]
    profile_picture: Optional[str]

class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str

class UserProfileSchema(BaseModel):
    name: str
    email: str
    phone_number: str
    date_of_birth: date
    address: str
    gender: str
    profile_picture: Optional[str] = None

    @classmethod
    def from_orm(cls, obj):
        obj_dict = obj.__dict__.copy()
        if obj.profile_picture:
            obj_dict['profile_picture'] = obj.profile_picture.url
        else:
            obj_dict['profile_picture'] = None
        return super().from_orm(obj_dict)

    class Config:
        from_attributes = True
