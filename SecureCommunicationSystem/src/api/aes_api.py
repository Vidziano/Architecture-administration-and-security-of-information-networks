import uuid
import json
import os
from fastapi import APIRouter, HTTPException
from src.services.aes_service import AesService
from src.models.aes_key import AesKey

router = APIRouter(prefix="/api/aes", tags=["AES API"])

# === Абсолютний шлях до AES файлу (біля main.py) ===
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AES_KEYS_FILE = os.path.join(PROJECT_ROOT, "aes_storage.json")

aes_storage: dict[str, AesKey] = {}
aes_service = AesService()


def save_storage():
    """Зберігає AES ключі у JSON."""
    with open(AES_KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump({k: v.model_dump() for k, v in aes_storage.items()}, f, ensure_ascii=False, indent=4)


def load_storage():
    """Завантажує AES ключі з JSON, якщо файл існує."""
    if os.path.exists(AES_KEYS_FILE):
        with open(AES_KEYS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for key, value in data.items():
                aes_storage[key] = AesKey(**value)
        print(f" Завантажено {len(aes_storage)} AES ключів із {AES_KEYS_FILE}")
    else:
        print(f" Файл {AES_KEYS_FILE} не знайдено. Створиться новий при генерації.")


# Завантаження при старті
load_storage()


@router.post("/generate")
def generate_aes_keys():
    """Генерує AES ключ і IV, зберігає у JSON."""
    new_id = str(uuid.uuid4())
    aes_key = aes_service.generate_secret_key()
    aes_storage[new_id] = aes_key
    save_storage()
    return {
        "id": new_id,
        "key": aes_key.key,
        "iv": aes_key.iv
    }


@router.post("/encrypt")
def encrypt_aes(data: dict):
    """Шифрує текст за допомогою AES."""
    key = data.get("key")
    iv = data.get("iv")
    plain_text = data.get("plain_text")

    if not key or not iv or not plain_text:
        raise HTTPException(status_code=400, detail="Передайте key, iv та plain_text")

    aes_key = AesKey(key=key, iv=iv)
    encrypted = aes_service.encrypt(aes_key, plain_text)
    return {"encrypted_text": encrypted}


@router.post("/decrypt")
def decrypt_aes(data: dict):
    """Розшифровує текст за допомогою AES."""
    key = data.get("key")
    iv = data.get("iv")
    cipher_text = data.get("cipher_text")

    if not key or not iv or not cipher_text:
        raise HTTPException(status_code=400, detail="Передайте key, iv та cipher_text")

    aes_key = AesKey(key=key, iv=iv)
    decrypted = aes_service.decrypt(aes_key, cipher_text)
    return {"decrypted_text": decrypted}
