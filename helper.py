from datetime import datetime, timedelta, timezone
import os
import bcrypt
import jwt

# Read secret from environment to avoid committing secrets to source control.
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_DO_NOT_USE_IN_PROD")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


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


# Helper 2: Create the JWT string
def create_access_token(data: dict):
    to_encode = data.copy()

    # Set the expiration time
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})

    # Sign the JWT using our SECRET_KEY and the HS256 algorithm
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt
