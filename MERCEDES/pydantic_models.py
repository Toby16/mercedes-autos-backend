from typing import Optional
from pydantic import BaseModel, EmailStr, Field


# Sign up takes only email & password
class PYDANTIC_AUTH_SIGNUP(BaseModel):
    email: EmailStr = Field(examples=["test@example.com"])
    password: str = Field(examples=["testpassword"])


class PYDANTIC_AUTH_LOGIN(BaseModel):
    username: str = Field(examples=["test@example.com", "testusername"])
    password: str = Field(examples=["testpassword"])


class PYDANTIC_AUTH_SEND_OTP(BaseModel):
    # use either username/email/user_id
    username: str = Field(examples=[
        "test@example.com",
        "SEC-1234567USR",
        "test_username"
    ])

class PYDANTIC_AUTH_VERIFY_OTP(BaseModel):
    # use either username/email/user_id
    username: str = Field(examples=[
        "test@example.com",
        "SEC-1234578USR",
        "test_username"
    ])
    otp_code: str = Field(examples=[
        "1234",
        "v53t"
    ])
