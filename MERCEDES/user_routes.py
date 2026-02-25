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

from MERCEDES.helper import (
    decode_jwt, generate_token,
    get_token)
from MERCEDES.models import (
    User_Table)
from MERCEDES.pydantic_models import (
    PYDANTIC_USER_UPDATE_PROFILE, PYDANTIC_USER_CHANGE_PASSWORD,
    PYDANTIC_USER_FORGOT_PASSWORD)

user_base_url = "/api/user"


@app.get(user_base_url+"/get/profile", status_code=status.HTTP_200_OK, tags=["USER"])
@app.get(user_base_url+"/get/profile/", status_code=status.HTTP_200_OK, tags=["USER"])
def get_profile(db: db_dependency, token: str = Depends(get_token)):
    # get user's profile info via validated token
    payload = decode_jwt(token)

    # check if user exists
    check_user = db.query(User_Table).filter(User_Table.user_id == payload["user_id"]).first()
    if check_user is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid token!/User does not exist!",
                "message": "Kindly input new token!"
            }
        )
    if check_user.is_activated is False:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Account not activated!",
                "message": "Kindly activate account!",
                "user_id": check_user.username
            }
        )

    # if user exists and is activated
    username = check_user.username
    user_id = check_user.user_id
    email = check_user.email
    profile_photo = check_user.profile_photo

    data = {
        "user_id": user_id,
        "username": username,
        "email": email,
        "photo_url": profile_photo
    }
    token = generate_token(data)
    token = token["token"]
    data.pop("user_id")

    return {
        "statusCode": 200,
        "message": "Success!",
        "data": data,
        "token": token
    }


@app.post(user_base_url+"/update/profile", status_code=status.HTTP_200_OK, tags=["USER"])
@app.post(user_base_url+"/update/profile/", status_code=status.HTTP_200_OK, tags=["USER"])
def update_profile(
    pyd_data: PYDANTIC_USER_UPDATE_PROFILE,
    db: db_dependency, token: str = Depends(get_token)):
    # update profile of an authenticated user
    payload = decode_jwt(token)

    # check if user exists
    check_user = db.query(User_Table).filter(User_Table.user_id == payload["user_id"]).first()
    if check_user is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid token!/User does not exist!",
                "message": "Kindly input new token!"
            }
        )
    if check_user.is_activated is False:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Account not activated!",
                "message": "Kindly activate account!",
                "user_id": check_user.username  
            }
        )

    data = {
        "user_id": check_user.user_id,
        "username": check_user.username,
        "email": check_user.email
    }
    token = generate_token(data)
    token = token["token"]

    # if input username is same for user
    if check_user.username == pyd_data.username:
        return {
            "statusCode": 200,
            "message": "user profile updated!",
            "username": check_user.username,
            "token": token
        }

    # check if input username belongs to some other user
    validate_username = db.query(
        User_Table).filter(User_Table.username == pyd_data.username).first()
    if validate_username is not None:
        if (check_user.user_id).lower() != (validate_username.user_id).lower():
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Username not available!",
                    "message": "Kindly input new username!",
                    "token": token
                }
            )

    # update username
    check_user.username = pyd_data.username
    # db.add(check_user)
    db.commit()

    return {
        "statusCode": 200,
        "message": "user profile updated!",
        "user_id": check_user.username,
        "token": token
    }


@app.delete(user_base_url+"/delete/profile", status_code=status.HTTP_200_OK, tags=["USER"])
@app.delete(user_base_url+"/delete/profile/", status_code=status.HTTP_200_OK, tags=["USER"])
def delete_profile(
    db: db_dependency, token: str = Depends(get_token)):
    # delete profile of an authenticated user
    payload = decode_jwt(token)

    # check if user exists
    check_user = db.query(User_Table).filter(User_Table.user_id == payload["user_id"]).first()
    if check_user is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid token!/User does not exist!",
                "message": "Kindly input new token!"
            }
        )
    if check_user.is_activated is False:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Account not activated!",
                "message": "Kindly activate account!",
                "user_id": check_user.username
            }
        )

    username = check_user.username
    # delete account
    db.delete(check_user)
    db.commit()

    return {
        "statusCode": 200,
        "message": "{} deleted successfully!".format(username)
    }


# change password & forgot password
@app.post(user_base_url+"/change/password", status_code=status.HTTP_200_OK, tags=["USER"])
@app.post(user_base_url+"/change/password/", status_code=status.HTTP_200_OK, tags=["USER"])
def change_password(
    pyd_data: PYDANTIC_USER_CHANGE_PASSWORD,
    db: db_dependency, token: str = Depends(get_token)):
    # change password of an authenticated user
    payload = decode_jwt(token)

    # check if user exists
    check_user = db.query(User_Table).filter(User_Table.user_id == payload["user_id"]).first()
    if check_user is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid token!/User does not exist!",
                "message": "Kindly input new token!"
            }
        )
    if check_user.is_activated is False:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Account not activated!",
                "message": "Kindly activate account!",
                "user_id": check_user.username
            }
        )

    data = {
        "user_id": check_user.user_id,
        "username": check_user.username,
        "email": check_user.email
    }
    old_password=pyd_data.current_password
    new_password=pyd_data.new_password
    token = generate_token(data)
    token = token["token"]

    # compare password
    password_check = argon2.verify(old_password, check_user.password)
    if password_check is False:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Incorrect current password!",
                "message": "Kindly input correct password!",
                "user_id": check_user.username,
                "token": token
            })
    # hash new password
    new_password_hash_bcrypt = argon2.hash(new_password)
    slug_ = (new_password)[::-1]
    # store to db
    check_user.password = new_password_hash_bcrypt
    check_user.slug = slug_

    db.commit()
    return {
        "statusCode": 200,
        "message": "user password updated!",
        "user_id": check_user.username,
        "token": token
    }

@app.post(user_base_url+"/forgot/password", status_code=status.HTTP_200_OK, tags=["USER"])
@app.post(user_base_url+"/forgot/password/", status_code=status.HTTP_200_OK, tags=["USER"])
def forgot_password(
    pyd_data: PYDANTIC_USER_FORGOT_PASSWORD,
    db: db_dependency, token: str = Depends(get_token)):
    # update password of a user after verified otp
    payload = decode_jwt(token)

    # check if user exists
    check_user = db.query(User_Table).filter(User_Table.user_id == payload["user_id"]).first()
    if check_user is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid token!/User does not exist!",
                "message": "Kindly input new token!"
            }
        )
    if check_user.is_activated is False:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Account not activated!",
                "message": "Kindly activate account!",
                "user_id": check_user.username
            }
        )

    data = {
        "user_id": check_user.user_id,
        "username": check_user.username,
        "email": check_user.email
    }
    new_password=pyd_data.new_password
    token = generate_token(data)
    token = token["token"]

    # hash new password
    new_password_hash_bcrypt = argon2.hash(new_password)
    slug_ = (new_password)[::-1]
    # store to db
    check_user.password = new_password_hash_bcrypt
    check_user.slug = slug_

    db.commit()
    return {
        "statusCode": 200,
        "message": "user password updated!",
        "user_id": check_user.username,
        "token": token
    }
