import os
from uuid import uuid4
from loguru import logger
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from database.mongo_connection import mongo_client
from routers.users.router import router as registration
from services.users_related import gather_correct_user_data
from database.collections.collections import create_basic_collections
from constants import DB_AUTH_NAME, CLN_USERS, ADMIN_ROLE, CELERY_WORKER
from routers.users.crud import db_get_user_by_username, db_create_new_user


load_dotenv('.env')

log_dir = 'logs/'
os.makedirs(log_dir, exist_ok=True)

logger.add(
    os.path.join(log_dir, 'log.log'),
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
    # + FIRST ADMIN ACCOUNT +
    logger.info('Checking for `admin` account')
    admin_login: str = os.getenv('API_F_ADMIN_LOGIN')
    admin_password: str = os.getenv('API_F_ADMIN_PWD')
    admin_exist = await db_get_user_by_username(
        admin_login, DB_AUTH_NAME, CLN_USERS, db,
    )
    if admin_exist:
        logger.info("Admin account check complete. Already exist")
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
    # - FIRST ADMIN ACCOUNT -
    # + FIRST CELERY WORKER +
    logger.info('Checking for basic `celeryWorker` account')
    celery_login: str = os.getenv('CELERY_F_WORKER')
    celery_password: str = os.getenv('CELERY_F_WORKER_PWD')
    first_celery_exist = await db_get_user_by_username(
        celery_login, DB_AUTH_NAME, CLN_USERS, db,
    )
    if first_celery_exist:
        logger.info('Basic `celeryWorker` already exists.')
    else:
        logger.warning(
            "Basic 'celeryWorker' account check complete. It's not present."
            " Creating basic `celeryWorker` account."
        )
        celery_worker_data = {
            'username': celery_login,
            'userRole': CELERY_WORKER,
            'password': celery_password,
        }
        cor_celery_worker_data = await gather_correct_user_data(celery_worker_data)
        await db_create_new_user(
            cor_celery_worker_data, DB_AUTH_NAME, CLN_USERS, db
        )
        logger.info(
            "New basic `celeryWorker` account created."
        )
    # - FIRST CELERY WORKER -


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
