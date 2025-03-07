import jwt
import datetime
import os
from fastapi import HTTPException, Depends
from fastapi import Request
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Secret key for signing JWT
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY is missing! Set it in the .env file.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token expiration time in minutes

# OAuth2 scheme for authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")  # Fixed incorrect URL

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return pwd_context.hash(password)


# Fake database for testing authentication
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "full_name": "Test User",
        "email": "testuser@example.com",
        "hashed_password": pwd_context.hash("testpassword"),
        "disabled": False,
    }
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify if a password matches its hashed version."""
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str):
    """Authenticate user and return user data if valid."""
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: datetime.timedelta = None) -> str:
    """Generate JWT token with expiration time."""
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "sub": data["sub"]})  # Fixed payload
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_jwt_token(token: str) -> dict:
    """Decode JWT token and return payload or None if invalid."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token


def get_current_user(request: Request):
    """Extract JWT token from cookies and validate the user."""
    token = request.cookies.get("access_token")  # Read token from cookie
    if not token:
        raise HTTPException(status_code=401, detail="Token missing, please login")

    payload = decode_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    username: str = payload.get("sub")
    user = fake_users_db.get(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

