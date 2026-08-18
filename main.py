from datetime import datetime, timedelta, timezone
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
import uuid
import redis

# Connect to Redis
# Decode_responses=True ensures we get normal Python strings back, not bytes
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

app = FastAPI()


from pydantic import BaseModel

class TokenRefreshRequest(BaseModel):
    refresh_token: str


# 1. The Secret Key (NEVER put this in public code in a real app!)
SECRET_KEY = "my_super_secret_key_for_development_only"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 3. Dummy Database (We use this instead of setting up PostgreSQL for the tutorial)
fake_users_db = {
    "suraj": {
        "username": "suraj",
        "full_name": "Suraj Sharma",
        # This is a valid bcrypt hash for the password "secret123"
        "hashed_password": "$2b$12$gEKT2HvD/sv349z8QQuBXeIhcZZYOFkmc2sT6ImiSKu57KJcz3woK",
    }
}


# Helper 1: Verify the typed password against the hashed password
def verify_password(plain_password, hashed_password):
    # bcrypt only supports passwords up to 72 bytes.
    # Reject longer values to avoid runtime crashes.
    if plain_password is None:
        return False

    try:
        if len(str(plain_password).encode("utf-8")) > 72:
            return False
        return bcrypt.checkpw(str(plain_password).encode("utf-8"), str(hashed_password).encode("utf-8"))
    except ValueError:
        return False


# # Helper 2: Create the JWT string
# def create_access_token(data: dict):
#     to_encode = data.copy()

#     # Set the expiration time
#     expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     to_encode.update({"exp": expire})

#     # Sign the JWT using our SECRET_KEY and the HS256 algorithm
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

#     return encoded_jwt  so following function for building any type of token

# We make this a generic function so it can build ANY type of token
def create_token(data: dict, token_type: str, expires_delta: timedelta):
    to_encode = data.copy()
    
    # 1. Calculate the exact expiration time
    expire = datetime.now(timezone.utc) + expires_delta
    
    # 2. Generate the unique jti (JWT ID)
    token_id = str(uuid.uuid4())
    
    # 3. Inject our new claims into the payload
    to_encode.update({
        "exp": expire,
        "jti": token_id,
        "type": token_type  # Tells us if this is "access" or "refresh"
    })
    
    # 4. Sign and return the string
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# @app.post("/login")
# def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
#     # 1. Fetch user from our "database"
#     user_dict = fake_users_db.get(form_data.username)

#     # 2. Verify user exists AND password is correct
#     if not user_dict or not verify_password(form_data.password, user_dict["hashed_password"]):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )

#     # 3. Create the payload (claims)
#     token_payload = {"sub": user_dict["username"]}

#     # 4. Generate the signed JWT
#     access_token = create_access_token(data=token_payload)

#     # 5. Return it to the user.
#     return {"access_token": access_token, "token_type": "bearer"}


#new login endpoint with access and refresh token
@app.post("/login")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # 1. Fetch and verify user (Same as before)
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict or not verify_password(form_data.password, user_dict["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. The base payload only needs the subject (username)
    token_payload = {"sub": user_dict["username"]}
    
    # 3. Mint the Access Token (Lives for 15 minutes)
    access_token = create_token(
        data=token_payload, 
        token_type="access", 
        expires_delta=timedelta(minutes=15)
    )
    
    # 4. Mint the Refresh Token (Lives for 7 days)
    refresh_token = create_token(
        data=token_payload, 
        token_type="refresh", 
        expires_delta=timedelta(days=7)
    )

    # 5. Return BOTH tokens to the frontend
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }
# --- ADD THIS TO THE BOTTOM OF YOUR MAIN.PY ---

# 1. The Security Scheme
# This tells FastAPI: "Look for a Bearer token in the Authorization header. 
# If they don't have one, tell them to go to the '/login' endpoint to get it."
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
        # Step A: Decode the token using our Secret Key
        # If the token is expired or tampered with, this line throws an error immediately.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        
        # --- ADD THIS SECURITY CHECK ---
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not an access token"
            )
        
        # --- NEW CODE: THE REDIS BLOCKLIST CHECK ---
        jti = payload.get("jti")
        # If this jti exists in Redis, the token was revoked!
        if redis_client.get(jti) is not None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="This token has been revoked (logged out)."
            )
        # -------------------------------
        # Step B: Extract the username from the "sub" (subject) claim
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
            
    except jwt.InvalidTokenError:
        # Catches expired tokens, tampered signatures, or completely fake tokens
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
    # If the code reaches this line, we are 100% sure the user is authenticated.
    return {
        "message": "Welcome to the protected route!",
        "your_profile": current_user
    }

@app.post("/refresh")
def refresh_access_token(request: TokenRefreshRequest):
    try:
        # 1. Decode the refresh token (this automatically checks the expiration date too)
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # 2. CRITICAL: Make sure they didn't send an access token by mistake (or maliciously)
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid token type. Expected a refresh token."
            )
            
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid payload"
            )
            
    except jwt.InvalidTokenError:
        # Token is expired, tampered with, or revoked. The user must actually log in again.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Refresh token expired or invalid"
        )
        
    # 3. If we get here, the refresh token is valid! Mint a new 15-minute Access Token
    new_access_token = create_token(
        data={"sub": username}, 
        token_type="access", 
        expires_delta=timedelta(minutes=15)
    )
    
    # 4. Send it back to the frontend
    return {"access_token": new_access_token, "token_type": "bearer"}

@app.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    try:
        # 1. Decode the token (we don't check expiration here because 
        # PyJWT checks it automatically. If it's already expired, 
        # they are essentially logged out anyway).
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # 2. Extract the unique jti and the exact expiration time
        jti = payload.get("jti")
        exp = payload.get("exp")
        
        # 3. Calculate how many seconds this token has left to live
        # We subtract the current UTC time from the expiration timestamp
        now = datetime.now(timezone.utc).timestamp()
        time_left_to_live = int(exp - now)
        
        # 4. Save to Redis with a TTL (Time To Live)
        # If time_left_to_live is 300 seconds, Redis will auto-delete this record in 5 minutes
        if time_left_to_live > 0:
            # We use .set(key, value, ex=seconds) to set it with expiration
            redis_client.set(jti, "revoked", ex=time_left_to_live)

    except jwt.InvalidTokenError:
        # If the token is invalid or already expired, we don't care. 
        # Just tell the frontend they are logged out.
        pass

    return {"message": "Successfully logged out"}
#this redis thing will fail just needed to not worry it will work redis was for linux not for windows so skip this issue
