import uuid
import json
import os
from fastapi import APIRouter, HTTPException
from src.services.rsa_service import RsaService
from src.models.rsa_keys import RsaKeys

router = APIRouter(prefix="/api/rsa", tags=["RSA API"])

# === Абсолютний шлях до файлу для збереження ключів  ===
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RSA_KEYS_FILE = os.path.join(PROJECT_ROOT, "rsa_storage.json")

# Пам’ять для ключів
rsa_storage: dict[str, RsaKeys] = {}

rsa_service = RsaService()


# === Збереження у JSON ===
def save_storage():
    """Зберігає всі ключі RSA у JSON."""
    with open(RSA_KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump({k: v.model_dump() for k, v in rsa_storage.items()}, f, ensure_ascii=False, indent=4)


def load_storage():
    """Завантажує ключі RSA з JSON, якщо файл існує."""
    if os.path.exists(RSA_KEYS_FILE):
        with open(RSA_KEYS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for key, value in data.items():
                rsa_storage[key] = RsaKeys(**value)
        print(f" Завантажено {len(rsa_storage)} RSA ключів із {RSA_KEYS_FILE}")
    else:
        print(f" Файл {RSA_KEYS_FILE} не знайдено. Створиться новий при генерації.")


# Завантаження при запуску сервера
load_storage()


@router.post("/generate")
def generate_rsa_keys():
    """Генерує нову пару RSA ключів і зберігає у пам’яті та JSON."""
    new_id = str(uuid.uuid4())
    keys = rsa_service.generate_keys()
    rsa_storage[new_id] = keys
    save_storage()
    return {
        "id": new_id,
        "public_key": keys.public_key,
        "private_key": keys.private_key
    }


@router.get("/public-key/{id}")
def get_rsa_public_key(id: str):
    """Повертає публічний ключ за ID."""
    if id not in rsa_storage:
        raise HTTPException(status_code=404, detail="Ключ за таким ID не знайдено")
    return {"public_key": rsa_storage[id].public_key}


@router.post("/encrypt")
def encrypt_rsa(data: dict):
    """Шифрує текст за допомогою RSA."""
    public_key = data.get("public_key")
    plain_text = data.get("plain_text")

    if not public_key or not plain_text:
        raise HTTPException(status_code=400, detail="Передайте public_key і plain_text")

    encrypted = rsa_service.encrypt(public_key, plain_text)
    return {"encrypted_text": encrypted}


@router.post("/decrypt")
def decrypt_rsa(data: dict):
    """Розшифровує текст за допомогою RSA."""
    private_key = data.get("private_key")
    cipher_text = data.get("cipher_text")

    if not private_key or not cipher_text:
        raise HTTPException(status_code=400, detail="Передайте private_key і cipher_text")

    decrypted = rsa_service.decrypt(private_key, cipher_text)
    return {"decrypted_text": decrypted}
