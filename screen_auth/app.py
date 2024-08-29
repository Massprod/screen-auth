import os
from uuid import uuid4
from loguru import logger
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from database.mongo_connection import mongo_client
from routers.users.router import router as registration
from constants import DB_AUTH_NAME, CLN_USERS, ADMIN_ROLE
from services.users_related import gather_correct_user_data
from database.collections.collections import create_basic_collections
from routers.users.crud import db_get_user_by_username, db_create_new_user


load_dotenv('.env')


logger.add(
    'logs/logs/log',
    rotation='50mb',
    retention='14 days',
    compression='zip',
    backtrace=True,
    diagnose=True,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await prepare_db()
    yield
    await close_db()


app: FastAPI = FastAPI(
    title='Screen Auth',
    version='0.0.1',
    description='Basic JWT authentication service',
    lifespan=lifespan,
    # TODO: remove debug, after completion.
    debug=True,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


app.include_router(registration, prefix='/users', tags=['Users'])


async def prepare_db():
    db = mongo_client.get_client()
    logger.info(
        'Started creating the basic DB collections'
    )
    await create_basic_collections(db)
    logger.info(
        'Finished creating the basic DB collections'
    )
    logger.info('Checking for admin account')
    admin_login = os.getenv('admin_login')
    admin_password = os.getenv('admin_password')
    admin_exist = await db_get_user_by_username(
        admin_login, DB_AUTH_NAME, CLN_USERS, db,
    )
    if admin_exist:
        logger.info("Admin account check complete. It's already exist")
    else:
        logger.warning(
            "Admin account check complete. It's not present."
            " Creating main Admin account."
        )
        admin_data = {
            'username': admin_login,
            'userRole': ADMIN_ROLE,
            'password': admin_password,
        }
        cor_admin_data = await gather_correct_user_data(admin_data)
        await db_create_new_user(
            cor_admin_data, DB_AUTH_NAME, CLN_USERS, db
        )
        logger.info(
            'New main Admin account created.'
        )


@app.middleware('http')
async def requests_logging(
        request: Request,
        call_next
):
    request_id = request.headers.get("X-Request-ID", str(uuid4()))
    logger.info(f"Incoming request: {request.method} {request.url} | Request ID: {request_id}")
    response = await call_next(request)
    logger.info(
        f"Completed request: {request.method} {request.url} |"
        f" Status: {response.status_code} |"
        f" Request ID: {request_id}"
    )
    response.headers["X-Request-ID"] = request_id
    return response


async def close_db():
    mongo_client.close_client()
