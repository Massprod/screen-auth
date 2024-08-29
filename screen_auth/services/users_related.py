from datetime import datetime, timezone
from services.pass_service import get_password_hash


async def time_w_timezone() -> datetime:
    return datetime.now(timezone.utc)


async def fill_create_user_data(
        user_data: dict,
) -> None:
    registration_date = await time_w_timezone()
    hashed_pass = await get_password_hash(user_data['password'])
    fill_data: dict = {
        'registrationDate': registration_date,
        'hashedPassword':hashed_pass,
        'isBanned': False,
        'banEndDate': None,
    }
    user_data.update(fill_data)


async def gather_token_response(
        token: str,
        token_type: str = 'bearer'
) -> dict:
    token_response = {
        'access_token': token,
        'token_type': token_type,
    }
    return token_response
