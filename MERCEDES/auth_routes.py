from MERCEDES import app
from fastapi import (HTTPException,
    File, UploadFile, Form, Depends,
    status, Request)
from MERCEDES.routes import db_dependency
import httpx
import json
import os
import random
import secrets
import time
from httpx import Timeout
from passlib.hash import argon2
from sqlalchemy import or_

from MERCEDES.helper import (
    decode_jwt, oauth,
    generate_otp, generate_token,
    get_token, smtp_send_otp)
from MERCEDES.models import (
    Otp_Table, User_Table)
from MERCEDES.pydantic_models import (
    PYDANTIC_AUTH_LOGIN, PYDANTIC_AUTH_SEND_OTP,
    PYDANTIC_AUTH_SIGNUP, PYDANTIC_AUTH_VERIFY_OTP)


auth_base_url = "/api/auth"


# GOOGLE SSO ROUTE - start #
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SECRET_KEY", "supersecret"))

# Redirect user to Google
@app.get(auth_base_url+"/google", status_code=status.HTTP_200_OK, tags=["AUTH"])
async def google_login(request: Request):
    redirect_uri = request.url_for("google_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)


# Google callback
@app.get(auth_base_url+"/google/callback", status_code=status.HTTP_200_OK, tags=["AUTH"])
async def google_callback(request: Request, db: db_dependency):
    token = await oauth.google.authorize_access_token(request)
    # userinfo = await oauth.google.parse_id_token(token, nonce, leeway=60)  # 60 seconds leeway
    user_info = token.get("userinfo")

    email = user_info["email"]
    name = user_info["name"]
    name = "".join(name.split())
    user_id = str(user_info["sub"])[:14]

    user = db.query(User_Table).filter(User_Table.email == email).first()
    # Auto signup
    if not user:
        # sso users get to use "none" as their password in auth_signup() & auth_login()
        # the above statement is an intended.hidden.feature
        user = User(
            email=email,
            username=name,
            user_id=user_id,
            password="none",
            slug="none"[::-1],
            is_activated=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    # Issue JWT
    # jwt_token = create_jwt(user.id)
    data = {
        "user_id": user_id,
        "email": email,
        "username": name
    }
    jwt_token = generate_token(data)
    access_token = jwt_token["token"]

    return {
        "statusCode": 200,
        "message": "SSO login successful",
        "user_id": name,
        "access_token": access_token
    }
# GOOGLE SSO ROUTE - end #


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
    # user_id = "ID_" + ''.join(random.choices(username.lower(), k=11))
    user_id = "ID_" + secrets.token_urlsafe(8)
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


# Login
@app.post(auth_base_url+"/login", status_code=status.HTTP_200_OK, tags=["AUTH"])
@app.post(auth_base_url+"/login/", status_code=status.HTTP_200_OK, tags=["AUTH"])
def auth_login(pyd_data: PYDANTIC_AUTH_LOGIN, db: db_dependency):
    if (not pyd_data.username) or (pyd_data.username in [ "", " ", None]):
        raise HTTPException(status_code=400, detail="input username/email!")

    username = pyd_data.username
    password = pyd_data.password

    # check if user exists either by email or username
    check_user = db.query(User_Table).filter(
        or_(
            User_Table.email == username,
            User_Table.username == username,
            User_Table.user_id == username
        )
    ).first()

    # if user doesn't exist or password is incorrect
    if (check_user is None) or (not argon2.verify(password, check_user.password)):
        # return bcrypt_sha256.verify(password, check_user.password)
        raise HTTPException(
            status_code=400,
            detail="invalid username or password!"
        )
    # check if validated user's account is activated
    if check_user.is_activated is False:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Account not activated!",
                "message": "Kindly activate account!",
                "user_id": username
            })

    # re-assign user_id/username/email from db
    user_id = check_user.user_id
    username = check_user.username
    email = check_user.email

    # tokenize user's input
    data = {
        "user_id": user_id,
        "username": username,
        "email": email
    }
    token = generate_token(data)
    token = token["token"]

    return {
        "statusCode": 200,
        "message": "login successful!",
        "user_id": pyd_data.username,
        "token": token
    }

# Verify account via token
@app.get(auth_base_url+"/activate", status_code=status.HTTP_200_OK, tags=["AUTH"])
@app.get(auth_base_url+"/activate/", status_code=status.HTTP_200_OK, tags=["AUTH"])
def activate_user(db: db_dependency, token: str = Depends(get_token)):
    # To activate user's account via token
    payload = decode_jwt(token)

    # check otp table to activate user
    check_user = db.query(User_Table).filter(User_Table.user_id == payload["user_id"]).first()
    if check_user is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid token!/User does not exist!",
                "message": "Kindly input new activation token!"
            }
        )
    if check_user.is_activated is True:
        return {
            "statusCode": 200,
            "message": "Account has been activated!",
            "user_id": check_user.username
        }
    check_user.is_activated = True
    db.commit()

    return {
        "statusCode": 200,
        "message": "Success! Account Activated!",
        "user_id": check_user.username
    }


@app.post(auth_base_url+"/send_otp", status_code=status.HTTP_200_OK, tags=["AUTH"])
@app.post(auth_base_url+"/send_otp/", status_code=status.HTTP_200_OK, tags=["AUTH"])
def send_otp(pyd_data: PYDANTIC_AUTH_SEND_OTP, db: db_dependency):
    # send/return otp for a user
    # username is email/username/user_id
    username = pyd_data.username

    # check if user exists either by email or username
    check_by_username = db.query(User_Table).filter(
        or_(
            User_Table.email == username,
            User_Table.username == username,
            User_Table.user_id == username
        )
    ).first()

    if check_by_username is None:
        raise HTTPException(
            status_code=400,
            detail="{} does not exist!".format(username)
        )

    user_id=check_by_username.user_id
    email=check_by_username.email
    username=check_by_username.username
    otp_code=generate_otp()
    otp_hash=argon2.hash(str(otp_code))
    otp_expires = str(time.time() + 300)  # otp lasts 5-minutes

    check_otp_table = db.query(Otp_Table).filter(Otp_Table.user_id == user_id).first()
    if check_otp_table is None:
        # if no record found for user, create new record
        new_otp = Otp_Table(
            user_id=user_id,
            otp_token=otp_hash,
            otp_expiry=otp_expires
        )
        db.add(new_otp)
        db.commit()
    else:
        # update existing otp record
        check_otp_table.otp_token=otp_hash
        check_otp_table.otp_expiry=otp_expires
        db.commit()

    smtp_data = smtp_send_otp(email, username, otp_code)
    # use smtp to send email
    return {
        "statusCode": 200,
        "message": smtp_data.get("message") or "error",
        "error": smtp_data.get("error") or None,
        "otp": smtp_data.get("otp") or None,
        "user_id": pyd_data.username
    }


@app.post(auth_base_url+"/verify_otp", status_code=status.HTTP_200_OK, tags=["AUTH"])
@app.post(auth_base_url+"/verify_otp/", status_code=status.HTTP_200_OK, tags=["AUTH"])
def verify_otp(pyd_data:PYDANTIC_AUTH_VERIFY_OTP, db: db_dependency):
    # validate otp for a user:
    username = pyd_data.username
    otp_code = pyd_data.otp_code

    # check if user exists
    # check if otp is expired

    # check if user exists either by email or username
    check_by_username = db.query(User_Table).filter(
        or_(
            User_Table.email == username,
            User_Table.username == username,
            User_Table.user_id == username
        )
    ).first()

    if check_by_username is None:
        raise HTTPException(
            status_code=400,
            detail="{} does not exist!".format(username)
        )

    # check otp_table to validate otp expiry and verify otp
    check_otp = db.query(Otp_Table).filter(Otp_Table.user_id == check_by_username.user_id).first()
    if float(check_otp.otp_expiry) <= time.time():
        raise HTTPException(
            status_code=400,
            detail={
                "error": "OTP Expired! Kindly request a new OTP!",
                "user_id": username
            }
        )

    otp_validate=argon2.verify(otp_code, check_otp.otp_token)
    if otp_validate is False:
        raise HTTPException(status_code=400, detail="invalid otp!")
    data = {
        "username": check_by_username.username,
        "user_id": check_by_username.user_id,
        "email": check_by_username.email
    }

    token = generate_token(data)
    token = token["token"]
    return {
        "statusCode": 200,
        "message": "OTP verified successfully!",
        "user_id": username,
        "token": token
    }


@app.get(auth_base_url+"/refresh_token", status_code=status.HTTP_200_OK, tags=["AUTH"])
@app.get(auth_base_url+"/refresh_token/", status_code=status.HTTP_200_OK, tags=["AUTH"])
def refresh_token(db: db_dependency, token: str = Depends(get_token)):
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
                "user_id": check_user.user_id
            }
        )

    # if user exists and is activated
    username = check_user.username
    user_id = check_user.user_id
    email = check_user.email

    data = {
        "user_id": user_id,
        "username": username,
        "email": email
    }
    token = generate_token(data)
    token = token["token"]

    return {
        "statusCode": 200,
        "message": "Success!",
        "token": token
    }
