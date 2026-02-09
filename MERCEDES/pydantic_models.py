from typing import Optional
from pydantic import BaseModel, EmailStr, Field


# Sign up takes only email & password
class PYDANTIC_AUTH_SIGNUP(BaseModel):
    email: EmailStr = Field(examples=["test@example.com"])
    password: str = Field(examples=["testpassword"])
