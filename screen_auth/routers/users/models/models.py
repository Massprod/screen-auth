from enum import Enum
from pydantic import BaseModel, Field, constr, field_validator
from constants import MANAGER_ROLE, OPERATOR_ROLE, LAB_PERSONAL_ROLE


class UserRoles(str, Enum):
    manager = MANAGER_ROLE
    operator = OPERATOR_ROLE
    labPersonal = LAB_PERSONAL_ROLE


class UserCreate(BaseModel):
    username: str = Field(...,
                          description='Unique `username` of the user',
                          pattern=r'^[a-zA-Z0-9_.-]+$',
                          min_length=3,
                          max_length=20,
                          examples=['JohnDoe', 'ElonBoy']
                          )
    password: str = Field(...,
                          description='`password` of the user',
                          pattern=r'^[A-Za-z\d@$!%*#?&]+$',
                          min_length=8,
                          max_length=50,
                          examples=['1Aa2345678!@', '98As7654312!_'],
                          )
    userRole: UserRoles = Field(...,
                                description='required role for the user',
                                examples=['manager', 'labPersonal', 'operator'],
                                )

    @field_validator('password')
    def password_complexity(cls, v: str) -> str:
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c.isalpha() for c in v):
            raise ValueError('Password must contain at least one letter')
        if not any(c in '@$!%*#?&' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v


class Token(BaseModel):
    access_token: str
    token_type: str = 'bearer'
