from loguru import logger
from pymongo.errors import PyMongoError
from fastapi import HTTPException, status
from motor.motor_asyncio import AsyncIOMotorClient
from routers.users.models.models import UserCreate
from services.mongo_related import (
    get_db_collection,
    log_db_record,
    log_db_error_record
)


async def db_get_user_by_username(
        username: str,
        db_name: str,
        collection_name: str,
        db: AsyncIOMotorClient,
):
    collection = await get_db_collection(db, db_name, collection_name)
    log_db: str = await log_db_record(db_name, collection_name)
    logger.info(
        f'Searching for a user with `username` = {username}' + log_db
    )
    query = {
        'username': username
    }
    try:
        result = await collection.find_one(query)
        logger.info(
            f'Successfully found requested data for `username` = {username}' + log_db
        )
        return result
    except PyMongoError as error:
        log_error: str = await log_db_error_record(error)
        logger.error(
            f'Error while searching for a user with `username`' + log_error + log_db
        )
        raise HTTPException(
            detail='Error while searching `username',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


async def db_create_a_new_user(
        user_data: dict,
        db_name: str,
        collection_name: str,
        db: AsyncIOMotorClient,
):
    collection = await get_db_collection(db, db_name, collection_name)
    log_db: str = await log_db_record(db_name, collection_name)
    username = user_data['username']
    logger.info(
        f'Creating a new user with `username` = {username}' + log_db
    )
    try:
        result = await collection.insert_one(user_data)
        logger.info(
            f'Successfully created a new user with `username` = {username}' + log_db
        )
        return result
    except PyMongoError as error:
        log_error: str = await log_db_error_record(error)
        logger.error(
            f'Error while creating user with `username` = {username}' + log_error + log_db
        )
        raise HTTPException(
            detail='Error while creating a new user',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
