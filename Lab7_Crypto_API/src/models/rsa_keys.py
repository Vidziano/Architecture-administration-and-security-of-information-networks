from pydantic import BaseModel

class RsaKeys(BaseModel):
    """Модель пари RSA-ключів."""
    public_key: str
    private_key: str
