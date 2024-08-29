from loguru import logger
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from database.mongo_connection import mongo_client
from services.jwt_service import create_access_token
from routers.users.models.models import UserCreate, Token, UsernameStr, PasswordStr
from fastapi import APIRouter, Body, Depends, HTTPException, status, Query
from constants import DB_AUTH_NAME, CLN_USERS, ACCESS_TOKEN_EXPIRE_MINUTES
from routers.users.crud import db_get_user_by_username_password, db_create_new_user
from services.users_related import (
    gather_correct_user_data,
    gather_token_response,
)
from services.pass_service import verify_password


router: APIRouter = APIRouter()


@router.post(
    path='/register',
    name='Register User',
    description='Creates a new User with provided credentials and `role`',
    response_model=Token,
)
async def post_route_register_user(
        user_data: UserCreate = Body(...,
                                     description='Required new User data'),
        db: AsyncIOMotorClient = Depends(mongo_client.depend_client),
):
    user_data = user_data.model_dump()
    exists = await db_get_user_by_username_password(
        user_data['username'], DB_AUTH_NAME, CLN_USERS, db
    )
    if exists:
        logger.info(
            f'User with `username` = {user_data['username']} already exists'
        )
        raise HTTPException(
            detail='User with provided `username` already exists',
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    correct_data = await gather_correct_user_data(user_data)
    await db_create_new_user(
        correct_data, DB_AUTH_NAME, CLN_USERS, db
    )
    token_data = {
        'sub': user_data['username'],
        'userRole': user_data['userRole'],
    }
    user_access_token = create_access_token(token_data, ACCESS_TOKEN_EXPIRE_MINUTES)
    return JSONResponse(
        content=await gather_token_response(user_access_token),
        status_code=status.HTTP_200_OK,
    )


@router.get(
    path='/login',
    name='Login User',
    description='Validates credentials and issues JWT in response',
    response_model=Token,
)
async def get_route_login_user(
        username: UsernameStr = Query(...,
                                      description='Required `username` credential',
                                      example='JohnDoe',
                                      ),
        password: PasswordStr = Query(...,
                                      description='Required `password` credential',
                                      example='1Aa2345678!@',
                                      ),
        db: AsyncIOMotorClient = Depends(mongo_client.depend_client),
):
    exists = await db_get_user_by_username_password(
        username, DB_AUTH_NAME, CLN_USERS, db,
    )
    if not exists:
        logger.warning(
            f'Attempt to login with incorrect credentials `username` = {username}'
        )
        raise HTTPException(
            detail='Incorrect username',
            status_code=status.HTTP_403_FORBIDDEN,
        )
    if not await verify_password(password, exists['hashedPassword']):
        logger.warning(
            f'Attempt to login with incorrect credentials `username` = {username} | `password` = {password}'
        )
        raise HTTPException(
            detail='Incorrect password',
            status_code=status.HTTP_403_FORBIDDEN,
        )
    token_data = {
        'sub': exists['username'],
        'userRole': exists['userRole'],
    }
    user_access_token = create_access_token(token_data, ACCESS_TOKEN_EXPIRE_MINUTES)
    return JSONResponse(
        content=await gather_token_response(user_access_token),
        status_code=status.HTTP_200_OK,
    )
