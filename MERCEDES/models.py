from sqlalchemy import (
    Boolean, Column, Integer,
    String, Text, Float, ForeignKey
)
from database import Base
from sqlalchemy.orm import relationship


# To store user's information
class User_Table(Base):
    __tablename__ = 'User_Table'
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(121), unique=True, index=True)
    user_id = Column(String(15), unique=True, index=True)  # non-editable
    username = Column(Text)  # editable
    password = Column(Text)  # encrypted
    profile_photo = Column(Text)

    slug = Column(Text)  # password-reverse/encrypted
    is_activated = Column(Boolean)
    

class Otp_Table(Base):
    # user otp credentials
    __tablename__ = "Otp_Table"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(18))
    otp_token = Column(Text)  # str/tokenized
    otp_expiry = Column(String(20))
