from pydantic import BaseModel

class SessionData(BaseModel):
    """Модель для збереження інформації про AES-сесію."""
    session_id: str
    aes_key: str
    iv: str
