from MERCEDES import app
from fastapi import HTTPException, File, UploadFile, Form, Depends, status
from MERCEDES.routes import db_dependency
import httpx
import json
import os
import random
import time
from httpx import Timeout
from passlib.hash import argon2

from MERCEDES.models import (
    User_Table)
from MERCEDES.pydantic_models import (
    PYDANTIC_AUTH_SIGNUP)

auth_base_url = "/api/auth"


# Signup
@app.post(auth_base_url+"/signup", status_code=status.HTTP_200_OK, tags=["AUTH"])
@app.post(auth_base_url+"/signup/", status_code=status.HTTP_200_OK, tags=["AUTH"])
def auth_signup(pyd_data: PYDANTIC_AUTH_SIGNUP, db: db_dependency):
    # validate email, and password inputs
    if (not pyd_data.email) or (pyd_data.email in [ "", " ", None]):
        raise HTTPException(status_code=400, detail="input email!")
    if (not pyd_data.password) or (pyd_data.password in [ "", " ", None]):
        raise HTTPException(status_code=400, detail="input password!")

    #  check if user's email already exists
    check_user = db.query(User_Table).filter(User_Table.email == pyd_data.email).first()
    if check_user is not None:
        # check if email is verified or not
        if check_user.is_activated is False:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Account not activated!",
                    "message": "Account already exists!",
                    "user_id": check_user.email
                }
            )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Kindly login!",
                "message": "Account already exists!",
                "user_id": check_user.email
            }
        )

    email = str(pyd_data.email)
    username = (str(pyd_data.email)).split("@")[0]
    user_id = "ID_" + ''.join(random.choices(username.lower(), k=11))
    password = pyd_data.password
    password_hash_bcrypt = argon2.hash(password)
    slug = (password)[::-1]  #  [ reversed user password ]

    new_user = User_Table(
        email=email,
        user_id=user_id,
        username=username,
        password=password_hash_bcrypt,
        slug=slug,
        is_activated=False
    )

    db.add(new_user)
    db.commit()
    
    # here anything can be passed as user_id ...
    # (even user_id itself)
    return {
        "statusCode": 201,
        "message": "Account created successfully!",
        "user_id": email
    }
