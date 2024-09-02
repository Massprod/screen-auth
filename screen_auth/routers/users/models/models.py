from enum import Enum
from fastapi import HTTPException, status
from pydantic import BaseModel, Field, constr, field_validator
from constants import (
    MANAGER_ROLE,
    OPERATOR_ROLE,
    LAB_PERSONAL_ROLE,
    USER_EXAMPLE_LOGIN,
    USER_EXAMPLE_PASSWORD,
    USER_NEW_EXAMPLE_PASSWORD,
    RESET_PASSWORD
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
        raise HTTPException(
            detail='Password must contain at least one digit',
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    if not any(c.isalpha() for c in password):
        raise HTTPException(
            detail='Password must contain at least one letter',
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    if not any(c in '@$!%*#?&' for c in password):
        raise HTTPException(
            detail='Password must contain at least one special character',
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
        )
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


class UserChangePassword(BaseModel):
    username: UsernameStr = Field(...,
                                  description='Required `username` credential',
                                  examples=[USER_EXAMPLE_LOGIN],
                                  )
    old_password: PasswordStr = Field(...,
                                      description='Required old `password` of the user',
                                      examples=[USER_EXAMPLE_PASSWORD],

                                      )
    new_password: PasswordStr = Field(...,
                                      description='Required new `password` of the user',
                                      examples=[USER_NEW_EXAMPLE_PASSWORD],
                                      )

    @field_validator('username')
    def preprocess_username(cls, username: str) -> str:
        return username.lower()

    @field_validator('old_password')
    def password_complexity(cls, password: str) -> str:
        return validate_password_complexity(password)

    @field_validator('new_password')
    def password_complexity(cls, password: str) -> str:
        return validate_password_complexity(password)


class UserResetPassword(BaseModel):
    username: UsernameStr = Field(...,
                                  description='Required `username` credential',
                                  examples=[USER_EXAMPLE_LOGIN],
                                  )
    new_password: PasswordStr = Field(RESET_PASSWORD,
                                      description=f'Not Required `password` to set.'
                                                  f'If not provided, it will be set to default: {RESET_PASSWORD}')

    @field_validator('username')
    def preprocess_username(cls, username: str) -> str:
        return username.lower()

    @field_validator('new_password')
    def password_complexity(cls, password: str) -> str:
        return validate_password_complexity(password)
