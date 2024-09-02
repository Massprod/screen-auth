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
    DB_AUTH_NAME,
    CLN_USERS,
)
from database.mongo_connection import mongo_client
from routers.users.crud import db_get_user_by_username


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
        username = payload.get('sub')
        if username is None:
            logger.warning(
                f'Attempt to use token without correct data in it | Missing `sub`'
            )
            raise HTTPException(
                detail='Incorrect token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        user_role = payload.get('userRole')
        if user_role is None:
            logger.warning(
                f'Attempt to use token without correct data in it | Missing `userRole`'
            )
            raise HTTPException(
                detail='Incorrect token',
                status_code=status.HTTP_401_UNAUTHORIZED
            )
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
        role: str = payload.get('userRole')
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
        role: str = payload.get('userRole')
        if ADMIN_ROLE != role:
            logger.warning(
                f'Attempt to use incorrect ADMIN token = {token} | Not valid `userRole` = {role}'
            )
            raise HTTPException(
                detail='Invalid Token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        username = payload.get('sub')
        db = mongo_client.get_client()
        user_exists = await db_get_user_by_username(
            username, DB_AUTH_NAME, CLN_USERS, db
        )
        if user_exists is None:
            logger.warning(
                f'Attempt to use incorrect ADMIN token = {token} | Not existing `username` = {username}'
            )
            raise HTTPException(
                detail='Invalid Token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        user_role = user_exists['userRole']
        if user_role != role:
            logger.warning(
                f'Attempt to use incorrect ADMIN token = {token} |'
                f' `userRole` = {user_role} token has different role = {role}'
            )
            raise HTTPException(
                detail='Invalid Token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        if ADMIN_ROLE != user_role:
            logger.warning(
                f'Attempt to use incorrect ADMIN token = {token} | Incorrect `userRole` = {user_role}'
            )
            raise HTTPException(
                detail='Invalid Token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        return username
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
        role: str = payload.get('userRole')
        if MANAGER_ROLE != role and ADMIN_ROLE != role:
            logger.warning(
                f'Attempt to use incorrect MANAGER|ADMIN token = {token} | Not valid `userRole` = {role}'
            )
            raise HTTPException(
                detail='Invalid Token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        username = payload.get('sub')
        db = mongo_client.get_client()
        user_exists = await db_get_user_by_username(
            username, DB_AUTH_NAME, CLN_USERS, db
        )
        if user_exists is None:
            logger.warning(
                f'Attempt to use incorrect MANAGER|ADMIN token = {token} | Not existing `username` = {username}'
            )
            raise HTTPException(
                detail='Invalid Token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        if user_exists['isBlocked']:
            logger.warning(
                f'Attempt to use incorrect MANAGER|ADMIN token = {token} | BLocked `username` = {username}'
            )
            raise HTTPException(
                detail='Invalid Token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        user_role = user_exists['userRole']
        if user_role != role:
            logger.warning(
                f'Attempt to use incorrect MANAGER|ADMIN token = {token} |'
                f' `userRole` = {user_role} token has different role = {role}'
            )
            raise HTTPException(
                detail='Invalid Token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        if ADMIN_ROLE != user_role and MANAGER_ROLE != user_role:
            logger.warning(
                f'Attempt to use incorrect MANAGER|ADMIN token = {token} | Incorrect `userRole` = {user_role}'
            )
            raise HTTPException(
                detail='Invalid Token',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        return username
    except JWTError as error:
        logger.error(
            f'Error while verifying provided token | Error: {error}'
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid Token',
        )
