from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from constants import PRIVATE_KEY, PUBLIC_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES


def create_access_token(data: dict, expiration_delta: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expiration_delta)
    to_encode.update(
        {
            "exp": expire,
        }
    )
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
