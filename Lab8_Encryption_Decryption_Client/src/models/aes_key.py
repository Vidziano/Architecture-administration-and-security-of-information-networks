from pydantic import BaseModel

class AesKey(BaseModel):
    """Модель для зберігання секретного ключа та IV."""
    key: str
    iv: str
