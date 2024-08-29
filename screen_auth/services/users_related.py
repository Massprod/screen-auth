from datetime import datetime, timezone
from services.pass_service import get_password_hash


async def time_w_timezone() -> datetime:
    return datetime.now(timezone.utc)


async def gather_correct_user_data(
        user_data: dict,
) -> dict:
    registration_date = await time_w_timezone()
    hashed_pass = await get_password_hash(user_data['password'])
    cor_data: dict = {
        'username': user_data['username'].lower(),
        'userRole': user_data['userRole'],
        'registrationDate': registration_date,
        'hashedPassword': hashed_pass,
        'isBlocked': False,
        'blockEndDate': None,
        'blockedBy': None,
    }
    return cor_data


async def gather_token_response(
        token: str,
        token_type: str = 'bearer'
) -> dict:
    token_response = {
        'access_token': token,
        'token_type': token_type,
    }
    return token_response
