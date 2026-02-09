from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Mercedes-Autos API",
    version="1.0.0"
)


# List of allowed origins
"""
origins = [
    "http://localhost:5173",
    "http://localhost:3000",
]
"""
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allow specific origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)



from MERCEDES import models
from database import engine
models.Base.metadata.create_all(bind=engine)

from MERCEDES import (routes)
# from MERCEDES import (pydantic_models, helper)
