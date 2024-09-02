import datetime
from loguru import logger
from datetime import timezone
from motor.motor_asyncio import AsyncIOMotorClient
from database.mongo_connection import mongo_client
from fastapi.responses import JSONResponse, Response
from fastapi.security import OAuth2PasswordRequestForm
from services.pass_service import verify_password, get_password_hash
from fastapi import APIRouter, Body, Depends, HTTPException, status, Query
from services.jwt_service import create_access_token, verify_admin_token, verify_manager_token, verify_token
from routers.users.models.models import (
    UserCreate,
    Token,
    UsernameStr,
    UserResetPassword,
    UserRoles,
    UserChangePassword,
)
from constants import (
    DB_AUTH_NAME,
    CLN_USERS,
    ACCESS_TOKEN_EXPIRE_SECONDS,
    USER_EXAMPLE_LOGIN,
    USER_EXAMPLE_NEW_ROLE,
    ADMIN_ROLE,
)
from routers.users.crud import (
    db_get_user_by_username,
    db_create_new_user,
    db_block_user,
    db_unblock_user,
    db_update_user_password,
    db_change_user_role,
)
from services.users_related import (
    gather_correct_user_data,
    gather_token_response,
    time_w_timezone,
)


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
        manager_username: str = Depends(verify_manager_token),
        db: AsyncIOMotorClient = Depends(mongo_client.depend_client),
):
    user_data = user_data.model_dump()
    logger.info(
        f'{manager_username} attempts to register a new Username = {user_data['username']}'
    )
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
    correct_data = await gather_correct_user_data(user_data)
    await db_create_new_user(
        correct_data, DB_AUTH_NAME, CLN_USERS, db
    )
    token_data = {
        'sub': user_data['username'],
        'userRole': user_data['userRole'],
    }
    user_access_token = create_access_token(token_data, ACCESS_TOKEN_EXPIRE_SECONDS)
    return JSONResponse(
        content=await gather_token_response(user_access_token),
        status_code=status.HTTP_200_OK,
    )


@router.post(
    path='/token_refresh',
    name='Refresh Token',
    description='Updates expiration time and returns refreshed JWT in response',
    response_model=Token,
)
async def post_route_token_refresh(
        verified_token: dict = Depends(verify_token),
        db: AsyncIOMotorClient = Depends(mongo_client.depend_client),
):
    username = verified_token.get('sub')
    if username is None:
        logger.warning(
            f'Attempt to use token without correct data in it'
        )
        raise HTTPException(
            detail='Incorrect token',
            status_code=status.HTTP_403_FORBIDDEN,
        )
    exists = await db_get_user_by_username(
        username, DB_AUTH_NAME, CLN_USERS, db,
    )
    if not exists:
        logger.warning(
            f'Attempt to refresh token with incorrect credentials `username` = {username}'
        )
        raise HTTPException(
            detail='Incorrect username',
            status_code=status.HTTP_404_NOT_FOUND,
        )
    if exists and exists['isBlocked']:
        logger.warning(
            f'Attempt to refresh token for blocked `username` = {username}'
        )
        raise HTTPException(
            detail='Blocked',
            status_code=status.HTTP_403_FORBIDDEN,
        )
    refreshed_token = create_access_token(verified_token)
    return JSONResponse(
        content=await gather_token_response(refreshed_token),
        status_code=status.HTTP_200_OK,
    )


@router.post(
    path='/login',
    name='Login User',
    description='Validates credentials and issues JWT in response',
    response_model=Token,
)
async def get_route_login_user(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: AsyncIOMotorClient = Depends(mongo_client.depend_client),
):
    username = form_data.username.lower()
    password = form_data.password
    exists = await db_get_user_by_username(
        username, DB_AUTH_NAME, CLN_USERS, db,
    )
    if not exists:
        logger.warning(
            f'Attempt to login with incorrect credentials `username` = {username}'
        )
        raise HTTPException(
            detail='Incorrect username',
            status_code=status.HTTP_404_NOT_FOUND,
        )
    if not await verify_password(password, exists['hashedPassword']):
        logger.warning(
            f'Attempt to login with incorrect credentials `username` = {username} | `password` = {password}'
        )
        raise HTTPException(
            detail='Incorrect password',
            status_code=status.HTTP_403_FORBIDDEN,
        )
    if exists['isBlocked']:
        current_time = await time_w_timezone()
        # PyMongo returns TimeZone unaware `datetime` object => convert it.
        blocked_until = exists['blockEndDate'].replace(tzinfo=timezone.utc)
        if current_time >= blocked_until:
            logger.info(f'Lifting expired block from `username` = {username}')
            await db_unblock_user(
                'AutoExpired', username, DB_AUTH_NAME, CLN_USERS, db
            )
        else:
            logger.warning(
                f'Attempt to login on blocked account `username` = {username}'
            )
            raise HTTPException(
                detail='User blocked',
                status_code=status.HTTP_403_FORBIDDEN,
            )
    token_data = {
        'sub': exists['username'],
        'userRole': exists['userRole'],
    }
    user_access_token = create_access_token(token_data, ACCESS_TOKEN_EXPIRE_SECONDS)
    return JSONResponse(
        content=await gather_token_response(user_access_token),
        status_code=status.HTTP_200_OK,
    )


@router.patch(
    path='/block',
    name='Block User',
    description='Blocking user service access for provided time period',
)
async def patch_route_block_user(
        username: UsernameStr = Query(...,
                                      description='Required `username` credential',
                                      example=USER_EXAMPLE_LOGIN,
                                      ),
        block_seconds: int = Query(...,
                                   description='Block period in seconds',
                                   example=10,
                                   ),
        admin_username: str = Depends(verify_admin_token),
        db: AsyncIOMotorClient = Depends(mongo_client.depend_client),
):
    unblock_date = (await time_w_timezone()) + datetime.timedelta(seconds=block_seconds)
    exist = await db_get_user_by_username(
        username, DB_AUTH_NAME, CLN_USERS, db
    )
    if not exist:
        logger.warning(
            f'`ADMIN = {admin_username} tried to block non existing `username` = {username}'
        )
        raise HTTPException(
            detail='Username Not Found',
            status_code=status.HTTP_404_NOT_FOUND,
        )
    if ADMIN_ROLE == exist['userRole']:
        logger.warning(
            f'ADMIN = {admin_username} tried to block another ADMIN `username` = {username}'
        )
        raise HTTPException(
            detail="ADMIN can't be blocked",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    result = await db_block_user(
        admin_username, username, unblock_date, DB_AUTH_NAME, CLN_USERS, db
    )
    return Response(
        status_code=status.HTTP_200_OK
    )


@router.patch(
    path='/unblock',
    name='Unblock User',
    description='Unblocking user service access',
)
async def patch_route_unblock_user(
        username: UsernameStr = Query(...,
                                      description='Required `username` credential',
                                      example=USER_EXAMPLE_LOGIN,
                                      ),
        admin_username: str = Depends(verify_admin_token),
        db: AsyncIOMotorClient = Depends(mongo_client.depend_client),
):
    result = await db_unblock_user(
        admin_username, username, DB_AUTH_NAME, CLN_USERS, db
    )
    if 0 == result.matched_count:
        logger.info(
            f'`username` = {username} NotFound'
        )
        raise HTTPException(
            detail='Username Not Found',
            status_code=status.HTTP_404_NOT_FOUND,
        )
    return Response(
        status_code=status.HTTP_200_OK,
    )


@router.patch(
    path='/change_password',
    name='Change Password',
    description='Changing user access password',
)
async def patch_route_change_user_password(
        new_user_data: UserChangePassword = Body(...,
                                                 description='Required user data:'
                                                             ' `username`, `old_password`, `new_password`',
                                                 ),
        admin_username: str = Depends(verify_admin_token),
        db: AsyncIOMotorClient = Depends(mongo_client.depend_client),
):
    user_data = new_user_data.model_dump()
    username, old_password, new_password = user_data['username'], user_data['old_password'], user_data['new_password']
    logger.info(
        f'ADMIN = {admin_username} attempts to change `username` = {username} password'
    )
    if old_password == new_password:
        logger.warning(
            f'ADMIN = {admin_username} provided equal passwords data | Rejected'
        )
        raise HTTPException(
            detail='Equal credentials provided',
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    exist = await db_get_user_by_username(
        username, DB_AUTH_NAME, CLN_USERS, db
    )
    if not exist:
        logger.warning(
            f"ADMIN = {admin_username} tried to change password for non existing `username` = {username}"
        )
        raise HTTPException(
            detail='Not Found',
            status_code=status.HTTP_404_NOT_FOUND,
        )
    if ADMIN_ROLE == exist['userRole'] and username != admin_username:
        logger.warning(
            f'ADMIN = {admin_username} tried to change password of another ADMIN = {username}'
        )
        raise HTTPException(
            detail='ADMIN password can be changed only by its owner',
            status_code=status.HTTP_403_FORBIDDEN,
        )
    correct = await verify_password(old_password, exist['hashedPassword'])
    if not correct:
        logger.warning(
            f'ADMIN = {admin_username} provided incorrect `old_password` = {old_password} for `username` = {username}'
        )
        raise HTTPException(
            detail='Incorrect `old_password`',
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    new_pass_hash: str = await get_password_hash(new_password)
    result = await db_update_user_password(
        admin_username, username, new_pass_hash, DB_AUTH_NAME, CLN_USERS, db
    )
    return Response(status_code=status.HTTP_200_OK)


@router.patch(
    path='/reset_password',
    name='Reset Password',
    description='Reset current password of user',
)
async def patch_route_reset_user_password(
        user_data: UserResetPassword = Body(...,
                                            description='Required data for reset'),
        admin_username: str = Depends(verify_admin_token),
        db: AsyncIOMotorClient = Depends(mongo_client.depend_client),
):
    user_data = user_data.model_dump()
    username, reset_password = user_data['username'], user_data['new_password']
    logger.info(
        f'ADMIN = {admin_username} attempts to reset `username` = {username} password'
    )
    exists = await db_get_user_by_username(
        username, DB_AUTH_NAME, CLN_USERS, db
    )
    if not exists:
        logger.warning(
            f'ADMIN = {admin_username} tried to reset password for non existing `username` = {username}'
        )
        raise HTTPException(
            detail='Not Found',
            status_code=status.HTTP_404_NOT_FOUND,
        )
    if ADMIN_ROLE == exists['userRole'] and username != admin_username:
        logger.warning(
            f'ADMIN = {admin_username} tried to reset password of another ADMIN = {username}'
        )
        raise HTTPException(
            detail='ADMIN password can be reset only by its owner',
            status_code=status.HTTP_403_FORBIDDEN,
        )
    new_pass_hash: str = await get_password_hash(reset_password)
    result = await db_update_user_password(
        admin_username, username, new_pass_hash, DB_AUTH_NAME, CLN_USERS, db
    )
    return Response(status_code=status.HTTP_200_OK)


@router.patch(
    path='/change_role',
    name='Change Role',
    description='Changing current user role',
)
async def patch_route_change_user_role(
        username: UsernameStr = Query(...,
                                      description='Required `username` credential',
                                      example=USER_EXAMPLE_LOGIN,
                                      ),
        new_role: UserRoles = Query(...,
                                    description='Required new `userRole` to set',
                                    example=USER_EXAMPLE_NEW_ROLE,
                                    ),
        admin_username: str = Depends(verify_admin_token),
        db: AsyncIOMotorClient = Depends(mongo_client.depend_client),
):
    exists = await db_get_user_by_username(
        username, DB_AUTH_NAME, CLN_USERS, db
    )
    if not exists:
        logger.warning(
            f'ADMIN = {admin_username} tried to change `userRole` for non existing `username` = {username}'
        )
        raise HTTPException(
            detail='Username with provided `username` not found',
            status_code=status.HTTP_404_NOT_FOUND,
        )
    if ADMIN_ROLE == exists['userRole']:
        logger.warning(
            f"ADMIN = {admin_username} tried to change `userRole` for another ADMIN = {username}"
        )
        raise HTTPException(
            detail="ADMIN role can't be changed",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    result = await db_change_user_role(
        admin_username, username, new_role, DB_AUTH_NAME, CLN_USERS, db
    )
    return Response(status_code=status.HTTP_200_OK)
