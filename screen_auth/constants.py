from pathlib import Path


FLD_BASIC_SCHEMAS: str = 'database/collections/schemas'
# DB
DB_AUTH_NAME: str = 'screenAuth'
# CLN
CLN_USERS: str = 'users'
# ROLES
MANAGER_ROLE: str = 'manager'
LAB_PERSONAL_ROLE: str = 'labPersonal'
OPERATOR_ROLE: str = 'operator'
ADMIN_ROLE: str = 'admin'

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


# User Example
USER_EXAMPLE_LOGIN = 'JohnDoe'
USER_EXAMPLE_PASSWORD = '1Aa2345678!@'
USER_NEW_EXAMPLE_PASSWORD = '12345!@pI'
USER_EXAMPLE_NEW_ROLE = 'operator'
# ---
