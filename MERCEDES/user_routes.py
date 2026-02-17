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
    )

auth_base_url = "/api/user"
