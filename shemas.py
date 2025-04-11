from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import List, Optional

class UserAccountCreate(BaseModel):
    email: str
    password: str
    platform: str
    account_id: int

class UserAccountResponse(BaseModel):
    id: int
    email: str
    password: str
    platform: str
    created_at: datetime

    class Config:
        orm_mode = True