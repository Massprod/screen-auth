from uuid import uuid4
from loguru import logger
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from database.collections.collections import create_basic_collections
from database.mongo_connection import mongo_client
from routers.users.router import router as registration


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
