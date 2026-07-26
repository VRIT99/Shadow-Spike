import asyncio
from app.database import AsyncSessionLocal, init_db
from app.services.auth_service import create_user, generate_totp_secret
from app.models.user import UserRole

async def make_admin():
    await init_db()
    async with AsyncSessionLocal() as db:
        try:
            user = await create_user(
                db,
                email='admin@shadowspike.local',
                username='admin',
                password='Sh@D0m_$qlkf',
                full_name='Administrator',
                role=UserRole.ADMIN
            )
            # Do NOT set totp_secret/verified here — admin will scan QR on first login
            await db.commit()
            print('Admin created successfully! Login to setup Google Authenticator.')
        except Exception as e:
            print(f'Error: {e}')

asyncio.run(make_admin())