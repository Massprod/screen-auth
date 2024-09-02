from loguru import logger
from datetime import datetime
from pymongo.errors import PyMongoError
from fastapi import HTTPException, status
from motor.motor_asyncio import AsyncIOMotorClient
from services.mongo_related import (
    get_db_collection,
    log_db_record,
    log_db_error_record
)


async def db_make_user_data_json_friendly(user_data: dict) -> dict:
    user_data['_id'] = str(user_data['_id'])
    user_data['registrationDate'] = user_data['registrationDate'].isoformat()
    block_end = user_data.get('blockEndDate')
    if block_end:
        user_data['blockEndDate'] = block_end.isoformat()
    return user_data


async def db_get_user_by_username(
        username: str,
        db_name: str,
        collection_name: str,
        db: AsyncIOMotorClient,
):
    username = username.lower()
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
            detail='Interval Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


async def db_create_new_user(
        user_data: dict,
        db_name: str,
        collection_name: str,
        db: AsyncIOMotorClient,
):
    collection = await get_db_collection(db, db_name, collection_name)
    log_db: str = await log_db_record(db_name, collection_name)
    user_data['username'] = user_data['username'].lower()
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
            detail='Interval Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


async def db_block_user(
        blocked_by: str,
        username: str,
        unblock_date: datetime,
        db_name: str,
        collection_name: str,
        db: AsyncIOMotorClient,
):
    collection = await get_db_collection(
        db, db_name, collection_name
    )
    log_db: str = await log_db_record(db_name, collection_name)
    username = username.lower()
    logger.info(
        f'ADMIN = {blocked_by} attempts to block `username` = {username}' + log_db
    )
    query = {
        'username': username,
    }
    update = {
        '$set': {
            'isBlocked': True,
            'blockedBy': blocked_by,
            'blockEndDate': unblock_date
        }
    }
    try:
        result = await collection.update_one(query, update)
        if 0 != result.matched_count:
            logger.info(
                f'ADMIN = {blocked_by} successfully blocked `username` = {username}' + log_db
            )
        return result
    except PyMongoError as error:
        log_error: str = await log_db_error_record(error)
        logger.error(
            f'Error while ADMIN = {blocked_by} tried to block `username` = {username}' + log_error + log_db
        )
        raise HTTPException(
            detail='Interval Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


async def db_unblock_user(
        unblocked_by: str,
        username: str,
        db_name: str,
        collection_name: str,
        db: AsyncIOMotorClient,
):
    collection = await get_db_collection(
        db, db_name, collection_name
    )
    log_db: str = await log_db_record(db_name, collection_name)
    username = username.lower()
    logger.info(
        f'ADMIN = {unblocked_by} attempts to unblock `username` = {username}' + log_db
    )
    query = {
        'username': username,
    }
    update = {
        '$set': {
            'isBlocked': False,
        }
    }
    try:
        result = await collection.update_one(query, update)
        if 0 != result.matched_count:
            logger.info(
                f'ADMIN = {unblocked_by} successfully unblocked `username` = {username}' + log_db
            )
        return result
    except PyMongoError as error:
        log_error: str = await log_db_error_record(error)
        logger.error(
            f'Error while ADMIN = {unblocked_by} tried to unblock `username` = {username}' + log_error + log_db
        )
        raise HTTPException(
            detail='Interval Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


async def db_update_user_password(
        changed_by: str,
        username: str,
        new_password_hash: str,
        db_name: str,
        collection_name: str,
        db: AsyncIOMotorClient,
):
    collection = await get_db_collection(
        db, db_name, collection_name
    )
    log_db: str = await log_db_record(db_name, collection_name)
    username = username.lower()
    logger.info(
        f"ADMIN = {changed_by} attempts to change password for `username` = {username}" + log_db
    )
    query = {
        'username': username,
    }
    update = {
        '$set': {
            'hashedPassword': new_password_hash,
        }
    }
    try:
        result = await collection.update_one(query, update)
        if 0 != result.matched_count:
            logger.info(
                f"ADMIN = {changed_by} successfully changed password for `username` = {username}" + log_db
            )
        return result
    except PyMongoError as error:
        log_error: str = await log_db_error_record(error)
        logger.error(
            f"Error while ADMIN = {changed_by} tried to"
            f" change password for `username` = {username}" + log_error + log_db
        )
        raise HTTPException(
            detail='Interval Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


async def db_change_user_role(
        changed_by: str,
        username: str,
        new_role: str,
        db_name: str,
        collection_name: str,
        db: AsyncIOMotorClient,
):
    collection = await get_db_collection(
        db, db_name, collection_name
    )
    log_db: str = await log_db_record(db_name, collection_name)
    username = username.lower()
    logger.info(
        f'ADMIN = {changed_by} attempts to change `userRole` for `username` = {username}' + log_db
    )
    query = {
        'username': username,
    }
    update = {
        '$set': {
            'userRole': new_role,
        }
    }
    try:
        result = await collection.update_one(query, update)
        if 0 != result.matched_count:
            logger.info(
                f"ADMIN = {changed_by} successfully changed `userRole` for `username` = {username}" + log_db
            )
        return result
    except PyMongoError as error:
        log_error: str = await log_db_error_record(error)
        logger.error(
            f'Error while ADMIN = {changed_by} tried to'
            f' change `userRole` for `username` = {username}' + log_error + log_db
        )
        raise HTTPException(
            detail='Interval Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


async def db_get_users_data(
        only_blocked: bool,
        db_name: str,
        collection_name: str,
        db: AsyncIOMotorClient,
):
    collection = await get_db_collection(
        db, db_name, collection_name
    )
    log_db: str = await log_db_record(db_name, collection_name)
    query = {}
    if only_blocked:
        query.update({
            'isBlocked': True
        })
    try:
        result = await collection.find(query).to_list(length=None)
        return result
    except PyMongoError as error:
        log_error: str = await log_db_error_record(error)
        logger.error(
            f'Error while getting users data' + log_error + log_db
        )
        raise HTTPException(
            detail='Interval Server Error',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
