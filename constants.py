from pathlib import Path
from os import getenv


FLD_BASIC_SCHEMAS: str = 'database/collections/schemas'
# DB
DB_AUTH_NAME: str = getenv('API_MONGO_DB_NAME', 'screenAuth')
# CLN
CLN_USERS: str = 'users'
# ROLES
MANAGER_ROLE: str = 'manager'
LAB_PERSONAL_ROLE: str = 'labPersonal'
OPERATOR_ROLE: str = 'operator'
ADMIN_ROLE: str = 'admin'
CELERY_WORKER: str = 'celeryWorker'
SYSTEM_ROLES: set[str] = {CELERY_WORKER}

# JWT_token config
PRIVATE_KEY_PATH = Path('certificates/private_key.pem')
PUBLIC_KEY_PATH = Path('certificates/public_key.pem')

with open(PRIVATE_KEY_PATH, 'r') as key_file:
    PRIVATE_KEY = key_file.read()

with open(PUBLIC_KEY_PATH, 'r') as key_file:
    PUBLIC_KEY = key_file.read()

ALGORITHM = getenv('jwt_algorithm')
ACCESS_TOKEN_EXPIRE_SECONDS = int(getenv('jwt_expiration'))
# ---
# RESET PASS
RESET_PASSWORD = getenv('STANDARD_RESET_PWD')


# User Example
USER_EXAMPLE_LOGIN = 'JohnDoe'
USER_EXAMPLE_PASSWORD = '1Aa2345678!@'
USER_NEW_EXAMPLE_PASSWORD = '12345!@pI'
USER_EXAMPLE_NEW_ROLE = 'operator'
# ---
