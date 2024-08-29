from loguru import logger
from fastapi.responses import JSONResponse
from constants import DB_AUTH_NAME, CLN_USERS
from motor.motor_asyncio import AsyncIOMotorClient
from database.mongo_connection import mongo_client
from services.jwt_service import create_access_token
from routers.users.models.models import UserCreate, Token
from fastapi import APIRouter, Body, Depends, HTTPException, status
from routers.users.crud import db_get_user_by_username, db_create_a_new_user
from services.users_related import fill_create_user_data, gather_token_response

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
    exists = await db_get_user_by_username(
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
    await fill_create_user_data(user_data)
    await db_create_a_new_user(
        user_data, DB_AUTH_NAME, CLN_USERS, db
    )
    token_data = {
        'sub': user_data['username'],
        'userRole': user_data['userRole'],
    }
    user_access_token = create_access_token(token_data, 1)
    return JSONResponse(
        content=await gather_token_response(user_access_token),
        status_code=status.HTTP_200_OK,
    )
