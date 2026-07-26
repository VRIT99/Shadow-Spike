"""
Script to update the admin user's password in the database.
Run: python update_admin_password.py
"""
import asyncio
from app.database import AsyncSessionLocal, init_db
from app.services.auth_service import get_user_by_email, hash_password

ADMIN_EMAIL = 'admin@shadowspike.local'
NEW_PASSWORD = 'Sh@D0m_$qlkf'

async def update_password():
    await init_db()
    async with AsyncSessionLocal() as db:
        user = await get_user_by_email(db, ADMIN_EMAIL)
        if not user:
            print(f'[ERROR] No user found with email: {ADMIN_EMAIL}')
            return
        user.hashed_password = hash_password(NEW_PASSWORD)
        # Reset any lockouts from previous failed attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        await db.commit()
        print(f'[SUCCESS] Password updated for {ADMIN_EMAIL}')
        print(f'[INFO]    Role: {user.role.value}')
        print(f'[INFO]    2FA Enabled: {user.totp_enabled}')

asyncio.run(update_password())
