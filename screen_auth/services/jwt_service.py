from loguru import logger
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from constants import (
    PRIVATE_KEY,
    PUBLIC_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_SECONDS,
    ADMIN_ROLE,
    MANAGER_ROLE,
)


def create_access_token(data: dict, expiration_delta: int = ACCESS_TOKEN_EXPIRE_SECONDS) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(seconds=expiration_delta)
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
    except JWTError as error:
        logger.error(
            f'Error while verifying provided token | Error: {error}'
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid token'
        )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='users/login')


async def get_current_user_role(token: str = Depends(oauth2_scheme)) -> str:
    logger.info(
        f'Verifying access token'
    )
    try:
        payload = verify_token(token)
        role: str | None = payload.get('userRole')
        if role is None:
            logger.warning(
                f'Attempt to use incorrect token = {token}'
            )
            raise HTTPException(
                detail='Invalid token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        return role
    except JWTError as error:
        logger.error(
            f'Error while verifying provided token | Error: {error}'
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid token'
        )


async def verify_admin_token(token: str = Depends(oauth2_scheme)) -> str:
    logger.info(
        f'Verifying ADMIN access token'
    )
    try:
        payload = verify_token(token)
        role: str | None = payload.get('userRole')
        if ADMIN_ROLE != role:
            logger.warning(
                f'Attempt to use incorrect ADMIN token = {token}'
            )
            raise HTTPException(
                detail='Invalid Token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        return payload.get('sub')
    except JWTError as error:
        logger.error(
            f'Error while verifying provided token | Error: {error}'
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid Token'
        )


async def verify_manager_token(token: str = Depends(oauth2_scheme)) -> str:
    logger.info(
        f'Verifying {MANAGER_ROLE.upper()} access token'
    )
    try:
        payload = verify_token(token)
        role: str | None = payload.get('userRole')
        if MANAGER_ROLE != role and ADMIN_ROLE != role:
            logger.warning(
                f'Attempt to use incorrect MANAGER|ADMIN token = {token}'
            )
            raise HTTPException(
                detail='Invalid Token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        return payload.get('sub')
    except JWTError as error:
        logger.error(
            f'Error while verifying provided token | Error: {error}'
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid Token',
        )
