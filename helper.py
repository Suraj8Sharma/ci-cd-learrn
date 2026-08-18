from datetime import datetime, timedelta, timezone
import bcrypt
import jwt

SECRET_KEY = "my_super_secret_key_for_development_only"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


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


# Helper 2: Create the JWT string
def create_access_token(data: dict):
    to_encode = data.copy()

    # Set the expiration time
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    # Sign the JWT using our SECRET_KEY and the HS256 algorithm
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt