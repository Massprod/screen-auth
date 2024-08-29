from enum import Enum
from pydantic import BaseModel, Field, constr, field_validator
from constants import (
    MANAGER_ROLE,
    OPERATOR_ROLE,
    LAB_PERSONAL_ROLE,
    USER_EXAMPLE_LOGIN,
    USER_EXAMPLE_PASSWORD
)


class Token(BaseModel):
    access_token: str
    token_type: str = 'bearer'


class UserRoles(str, Enum):
    manager = MANAGER_ROLE
    operator = OPERATOR_ROLE
    labPersonal = LAB_PERSONAL_ROLE


UsernameStr = constr(
    pattern=r'^[a-zA-Z0-9_.-]+$',
    min_length=3,
    max_length=20,
)

PasswordStr = constr(
    pattern=r'^[A-Za-z\d@$!%*#?&]+$',
    min_length=8,
    max_length=50,
)


def validate_password_complexity(password: str) -> str:
    if not any(c.isdigit() for c in password):
        raise ValueError('Password must contain at least one digit')
    if not any(c.isalpha() for c in password):
        raise ValueError('Password must contain at least one letter')
    if not any(c in '@$!%*#?&' for c in password):
        raise ValueError('Password must contain at least one special character')
    return password


class UserCreate(BaseModel):
    username: UsernameStr = Field(...,
                                  description='Unique `username` of the user',
                                  examples=[USER_EXAMPLE_LOGIN],
                                  )
    password: PasswordStr = Field(...,
                                  description='`password` of the user',
                                  examples=[USER_EXAMPLE_PASSWORD],
                                  )
    userRole: UserRoles = Field(...,
                                description='required role for the user',
                                examples=['manager', 'labPersonal', 'operator'],
                                )

    @field_validator('username')
    def preprocess_username(cls, username: str) -> str:
        return username.lower()

    @field_validator('password')
    def password_complexity(cls, password: str) -> str:
        return validate_password_complexity(password)
