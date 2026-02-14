from MERCEDES import app
from fastapi import status, Depends
from database import SessionLocal
from sqlalchemy.orm import Session
from typing import Annotated

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
db_dependency = Annotated[Session, Depends(get_db)]


#  [ INDEX/MISC ]
@app.get("/", status_code=status.HTTP_200_OK)
def index():
    return {
        "statusCode": 200,
        "message": "nothing to see here!"
    }

from MERCEDES import auth_routes
