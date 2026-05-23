from fastapi import Header, HTTPException
from config import ADMIN_API_KEY

async def verify_admin_key(x_api_key: str = Header(..., alias="X-API-Key")):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(403, "Clé admin invalide")
    return True
