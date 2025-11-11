from pydantic import BaseModel
from datetime import datetime

class SessionData(BaseModel):
    """Модель для збереження інформації про AES-сесію."""
    session_id: str
    aes_key: str
    iv: str
    expired_at: datetime  # нове поле
