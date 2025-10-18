import uuid
from fastapi import APIRouter, HTTPException
from src.services.rsa_service import RsaService
from src.models.rsa_keys import RsaKeys

router = APIRouter(prefix="/api/crypto-keys", tags=["RSA Keys"])

# "Сховище" у пам'яті
rsa_storage: dict[str, RsaKeys] = {}
rsa_service = RsaService()


@router.post("/generate/rsa-keys")
def generate_rsa_keys():
    """
    Генерує пару RSA-ключів, зберігає у пам’яті та повертає унікальний ID.
    """
    try:
        new_id = str(uuid.uuid4())
        keys = rsa_service.generate_keys()
        rsa_storage[new_id] = keys
        return {"id": new_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Помилка генерації ключів: {e}")


@router.get("/rsa-public-key/{id}")
def get_public_key(id: str):
    """
    Повертає публічний ключ за ID, якщо він є у пам’яті.
    """
    if id not in rsa_storage:
        raise HTTPException(status_code=404, detail="Ключ за таким ID не знайдено")

    return {"public_key": rsa_storage[id].public_key}
