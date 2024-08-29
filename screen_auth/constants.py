from pathlib import Path


FLD_BASIC_SCHEMAS: str = 'database/collections/schemas'
# DB
DB_AUTH_NAME: str = 'screenAuth'
# CLN
CLN_USERS: str = 'users'
MANAGER_ROLE: str = 'manager'
LAB_PERSONAL_ROLE: str = 'labPersonal'
OPERATOR_ROLE: str = 'operator'

# JWT_token config
PRIVATE_KEY_PATH = Path('certificates/private_key.pem')
PUBLIC_KEY_PATH = Path('certificates/public_key.pem')

with open(PRIVATE_KEY_PATH, 'r') as key_file:
    PRIVATE_KEY = key_file.read()

with open(PUBLIC_KEY_PATH, 'r') as key_file:
    PUBLIC_KEY = key_file.read()

ALGORITHM = 'RS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# ---
