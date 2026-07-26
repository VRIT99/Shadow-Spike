import asyncio
import os
import traceback
from dotenv import load_dotenv

# Force reload
load_dotenv(".env", override=True)

import app.config  # this triggers the config loading via pydantic

from app.services.email_service import send_password_reset_email

async def main():
    try:
        username = os.getenv('MAIL_USERNAME')
        print(f"MAIL_USERNAME is: '{username}'")
        if not username:
            print("ERROR: MAIL_USERNAME is empty in .env. Email cannot be sent.")
            return

        print(f"Sending test email to {username}...")
        await send_password_reset_email(username, "http://test")
        print("Function completed.")
    except Exception as e:
        print(f"Exception caught: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
