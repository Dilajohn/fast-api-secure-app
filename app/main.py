from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from app.auth import create_access_token, create_refresh_token, decode_token
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from secure import SecureHeaders
from fastapi.middleware.cors import CORSMiddleware
from app.users import router as user_router
from app.oauth import router as oauth_router

app = FastAPI()

# Secure headers setup
secure_headers = SecureHeaders()


# Dummy user
fake_user = {"username": "admin", "password": "1234", "role": "admin"}

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

@app.post("/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != fake_user["username"] or form_data.password != fake_user["password"]:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    user_data = {"sub": fake_user["username"], "role": fake_user["role"]}
    access = create_access_token(user_data)
    refresh = create_refresh_token(user_data)
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}

@app.post("/refresh", response_model=TokenResponse)
def refresh_token(refresh_token: str):
    user_data = decode_token(refresh_token)
    if not user_data:
        raise HTTPException(status_code=403, detail="Invalid refresh token")
    
    access = create_access_token({"sub": user_data["sub"], "role": user_data["role"]})
    return {"access_token": access, "refresh_token": refresh_token, "token_type": "bearer"}


@app.middleware("http")
async def set_secure_headers(request, call_next):
    response = await call_next(request)
    secure_headers.starlette(response)
    return response

# Optional: Add CORS Middleware for frontend/backend interaction
@app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Adjust for frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def set_secure_headers(request: Request, call_next):
    response = await call_next(request)
    secure_headers.starlette(response)
    return response

app.include_router(user_router)
app.include_router(oauth_router)

