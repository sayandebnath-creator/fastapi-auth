from fastapi import APIRouter, Depends
from routes.auth import get_current_user
from fastapi import APIRouter, Depends, HTTPException, Request
from jose import JWTError, jwt
import os


SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

router = APIRouter()

def get_current_user(request: Request):
    token = request.cookies.get("access_token") #read from cookies
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        payload = jwt.decode(token, SECRECT_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token has expired or is invalid")
    
    return{"username": username}
        


@router.get("/protected")
def protected_route(user: dict = Depends(get_current_user)):
    """Example of a protected route."""
    return {"message": f"Hello {user['sub']}, you are authenticated!"}
