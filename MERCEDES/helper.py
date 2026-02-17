from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends, HTTPException

import json, jwt, random, os, re, string, time
from SMTPEmail import SMTP
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import EmailMessage
from email.utils import formataddr
from email_validator import validate_email, EmailNotValidError

from dotenv import load_dotenv
load_dotenv()


# To check if an input is a valid email address
def email_validator(usr_email):
    try:
        emailinfo = validate_email(usr_email, check_deliverability=False)
        return (emailinfo.normalized).lower()
    except EmailNotValidError as e:
        return {
            "statusCode": 400,
            "error": str(e)
        }
    except exception as e:
        raise


# To decode a JWT token
def decode_jwt(token: str):
    #  [ TOKENIZATION ]
    JWT_SECRET = os.getenv("SECRET")
    JWT_ALGORITHM = os.getenv("ALGORITHM")

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        # Ensure the token includes "expires"
        if "expires" not in decoded_token:
            raise ValueError("Invalid Token")
        # Check token expiry
        if float(decoded_token["expires"]) <= time.time():
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Token expired!",
                    "message": "Kindly input new token!"
                }
            )
        return decoded_token  # if decoded_token["expires"] >= time.time() else None
    except jwt.ExpiredSignatureError:
        return {
            "statusCode": 401,
            "err": "Token has expired!"
        }
    except jwt.InvalidTokenError as e:
        return {
            "statusCode": 401,
            "err": "Invalid Token!",
            "error": str(e)
        }
        # raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise
        return {
            "statusCode": 400,
            "err": str(e)
        }


# To create JWT token from input data
def generate_token(data):
    payload_list = ["user_id", "email", "username"]
    payload = {}
    for i in payload_list:
        payload[i] = data[i]
    payload["expires"] = time.time() + 5400  # expiry time of 1hr 30mins

    #  [ TOKENIZATION ]
    JWT_SECRET = os.getenv("SECRET")
    JWT_ALGORITHM = os.getenv("ALGORITHM")
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return {
        "statusCode": 200,
        "message": "success",
        "token": token
    }


# To generate an alphanumeric 6 code otp
def generate_otp():
    alphnum = "".join(
        random.choices(string.ascii_letters + string.digits, k=6)
    )
    return alphnum


#  [ GET BEARER TOKEN FROM 'AUTHORIZATION' HEADER ]
security = HTTPBearer()
def get_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Token",
        )
    return credentials.credentials


# Template to send messages to user's email
def smtp_send_otp(email=None, username=None, otp_code=None):
    if (email is None) or (username is None) or (otp_code is None):
        return{
            "error": "input email, username, and otp_code"
        }

    """
    return {
        "error": "SMTP temporarily down!",
        "otp": otp_code
    }
    """

    try:
        # Create the email content
        msg = MIMEMultipart()
        sender_addr = os.getenv("SMTP_ACCOUNT")
        msg["From"] = formataddr(("Mercedes.teams", sender_addr))
        msg['To'] = email
        msg['Subject'] = 'One Time Password [ No-reply! ]'

        # Email body
        body = """
        hello {username}
        <br>
        otp code: {otp_code}
        """.format(username=username, otp_code=otp_code)

        msg.attach(MIMEText(body, 'html'))
        server = smtplib.SMTP(os.getenv("SMTP_SERVER"), 587)
        server.ehlo()  # Ensure the connection is established
        server.starttls()  # Secure the connection
        server.login(os.getenv("SMTP_ACCOUNT"), os.getenv("SMTP_PASSWORD"))
        server.send_message(msg)
        server.quit()  # Close the connection after sending the message

    except Exception as e:
        # raise
        return {
            "statusCode": 400,
            "error": str(e)
        }
    return {
        "statusCode": 200,
        "message": "success! - can't find OTP? check your spam messages!",
        "email": email,
        "otp": otp_code

    }
