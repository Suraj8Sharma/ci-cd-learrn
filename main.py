from datetime import datetime, timedelta, timezone
import os
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
)
from pydantic import BaseModel
import jwt
import uuid
import time

# --- IN-MEMORY REDIS MOCK FOR LOCAL DEVELOPMENT & TESTING ---


class InMemoryRedis:
    """Simple in-memory store that supports TTL for testing."""

    def __init__(self):
        self._store = {}

    def set(self, key: str, value: str, ex: int | None = None) -> bool:
        expire_at = (time.time() + ex) if ex else None
        self._store[key] = (value, expire_at)
        return True

    def get(self, key: str) -> str | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expire_at = entry
        if expire_at and time.time() > expire_at:
            del self._store[key]
            return None
        return value


# Use the mock directly
redis_client = InMemoryRedis()


app = FastAPI()


class TokenRefreshRequest(BaseModel):
    refresh_token: str


# Read secret from environment to avoid committing secrets to source control.
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_DO_NOT_USE_IN_PROD")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 3. Dummy Database
# We use this instead of setting up PostgreSQL for the tutorial.
fake_users_db = {
    "suraj": {
        "username": "suraj",
        "full_name": "Suraj Sharma",
        # This is a valid bcrypt hash for the password "secret123".
        "hashed_password": (
            "$2b$12$gEKT2HvD/sv349z8QQuBXeIhcZZYOFkmc2sT6ImiSKu57KJcz3woK"
        ),
    }
}


# Helper 1: Verify the typed password against the hashed password
def verify_password(plain_password, hashed_password):
    # bcrypt only supports passwords up to 72 bytes.
    # Reject longer values to avoid runtime crashes.
    if plain_password is None:
        return False

    try:
        pw_bytes = str(plain_password).encode("utf-8")
        hashed_bytes = str(hashed_password).encode("utf-8")
        if len(pw_bytes) > 72:
            return False
        return bcrypt.checkpw(pw_bytes, hashed_bytes)
    except ValueError:
        return False


# # Helper 2: Create the JWT string
# def create_access_token(data: dict):
#     to_encode = data.copy()
#
#     # Set the expiration time
#     expire = datetime.now(timezone.utc) + timedelta(
#         minutes=ACCESS_TOKEN_EXPIRE_MINUTES
#     )
#     to_encode.update({"exp": expire})
#
#     # Sign the JWT using our SECRET_KEY and the HS256 algorithm
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#
#     return encoded_jwt  so following function for building any type of token

# We make this a generic function so it can build ANY type of token
def create_token(data: dict, token_type: str, expires_delta: timedelta):
    to_encode = data.copy()

    # 1. Calculate the exact expiration time
    expire = datetime.now(timezone.utc) + expires_delta

    # 2. Generate the unique jti (JWT ID)
    token_id = str(uuid.uuid4())

    # 3. Inject our new claims into the payload
    to_encode.update(
        {
            "exp": expire,
            "jti": token_id,
            "type": token_type,
        }
    )

    # 4. Sign and return the string
    encoded_jwt = jwt.encode(
        to_encode, SECRET_KEY, algorithm=ALGORITHM
    )

    return encoded_jwt


# (old login helper removed to satisfy lint rules)


# new login endpoint with access and refresh token
@app.post("/login")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # 1. Fetch and verify user (Same as before)
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict or not verify_password(
        form_data.password, user_dict["hashed_password"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. The base payload only needs the subject (username)
    token_payload = {"sub": user_dict["username"]}

    # 3. Mint the Access Token (lives for 15 minutes)
    access_token = create_token(
        data=token_payload,
        token_type="access",
        expires_delta=timedelta(minutes=15),
    )

    # 4. Mint the Refresh Token (lives for 7 days)
    refresh_token = create_token(
        data=token_payload,
        token_type="refresh",
        expires_delta=timedelta(days=7),
    )

    # 5. Return BOTH tokens to the frontend
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

    # --- ADD THIS TO THE BOTTOM OF YOUR MAIN.PY ---

# --- ADD THIS TO THE BOTTOM OF YOUR MAIN.PY ---

# 1. The Security Scheme
# This tells FastAPI to look for a Bearer token in the Authorization header.
# If they don't have one, they should go to the '/login' endpoint to get it.


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# 2. The Dependency Function (The Bouncer)
# This function runs automatically BEFORE the route logic executes.
def get_current_user(token: str = Depends(oauth2_scheme)):

    # We define a standard error to throw if anything goes wrong
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Step A: Decode the token using our secret key. This will raise on
        # expired or tampered tokens.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Add a security check to ensure type is access
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not an access token",
            )

        # Check revocation list (in-memory redis for tests)
        jti = payload.get("jti")
        if redis_client.get(jti) is not None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="This token has been revoked (logged out).",
            )

        # Step B: Extract the username from the 'sub' claim
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception

    except jwt.InvalidTokenError:
        # Catches expired, tampered, or otherwise invalid tokens
        raise credentials_exception

    # Step C: Look up the user in our database
    user_dict = fake_users_db.get(username)
    if user_dict is None:
        raise credentials_exception

    # Step D: Hand the verified user dictionary over to the route!
    return user_dict


# 3. The Protected Route
# Notice the Depends(get_current_user). FastAPI will not run this function
# unless the get_current_user function succeeds first.


@app.get("/users/me")
def read_users_me(current_user: dict = Depends(get_current_user)):
    # If the code reaches this line, the user is authenticated.
    return {
        "message": "Welcome to the protected route!",
        "your_profile": current_user,
    }


@app.post("/refresh")
def refresh_access_token(request: TokenRefreshRequest):
    try:
        # Decode the refresh token (checks expiration)
        payload = jwt.decode(
            request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM]
        )

        # Make sure callers sent a refresh token (not an access token)
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type. Expected a refresh token.",
            )

        username: str = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid payload",
            )

    except jwt.InvalidTokenError:
        # Token is expired, tampered with, or invalid
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired or invalid",
        )

    # Mint a new short-lived access token
    new_access_token = create_token(
        data={"sub": username},
        token_type="access",
        expires_delta=timedelta(minutes=15),
    )

    return {"access_token": new_access_token, "token_type": "bearer"}


@app.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    try:
        # Decode token and mark its jti in the revocation list
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        jti = payload.get("jti")
        exp = payload.get("exp")

        now = datetime.now(timezone.utc).timestamp()
        time_left_to_live = int(exp - now)

        if time_left_to_live > 0:
            redis_client.set(jti, "revoked", ex=time_left_to_live)

    except jwt.InvalidTokenError:
        # Token invalid or expired — treat as logged out
        pass

    return {"message": "Successfully logged out"}
