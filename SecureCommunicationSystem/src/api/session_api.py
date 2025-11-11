import base64
from datetime import datetime
from fastapi import APIRouter, HTTPException, Header
from src.services.session_service import SessionService
from src.services.aes_service import AesService
from src.models.aes_key import AesKey
from src.services.rsa_service import RsaService
from dateutil import parser   

router = APIRouter(prefix="/api/session", tags=["Session API"])

# Єдині екземпляри сервісів
session_service = SessionService()
aes_service = AesService()
rsa_service = RsaService()


@router.get("/init")
def init_session():
    """Крок 1: Клієнт запитує випадковий публічний RSA ключ."""
    rsa_id, rsa_keys = session_service.get_random_rsa_pair()
    return {"rsa_id": rsa_id, "public_key": rsa_keys.public_key}


@router.post("/handshake")
def handshake(
    data: dict,
    x_rsa_id: str = Header(...),
    x_session_id: str = Header(...)
):
    """
    Крок 2: Сервер приймає зашифровані AES key + IV через заголовки.
    """
    encrypted_key = data.get("encrypted_key")
    encrypted_iv = data.get("encrypted_iv")

    if not encrypted_key or not encrypted_iv:
        raise HTTPException(status_code=400, detail="Missing AES parameters")

    # Отримуємо RSA пару за ідентифікатором
    rsa_keys = session_service.rsa_pool.get(x_rsa_id)
    if not rsa_keys:
        raise HTTPException(status_code=404, detail="RSA key not found")

    # Розшифровуємо AES key та IV
    aes_key_str = rsa_service.decrypt(rsa_keys.private_key, encrypted_key)
    iv_str = rsa_service.decrypt(rsa_keys.private_key, encrypted_iv)

    # Зберігаємо AES ключ у пам’яті
    session_service.save_session(x_session_id, AesKey(key=aes_key_str, iv=iv_str))
    return {"status": "handshake_successful", "session_id": x_session_id}


@router.post("/message")
def message(data: dict, x_session_id: str = Header(...)):
    """
    Крок 3: Сервер приймає AES-зашифроване повідомлення,
    розшифровує його, додає час і відправляє відповідь.
    """
    session = session_service.get_session(x_session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    #  Перевірка терміну дії сесії з урахуванням типів
    expired_at = session.expired_at
    if isinstance(expired_at, str):
        expired_at = parser.parse(expired_at)

    # Перевіряємо у форматі UTC
    if expired_at < datetime.utcnow():
        raise HTTPException(status_code=440, detail="Session expired")

    cipher_text = data.get("cipher_text")
    if not cipher_text:
        raise HTTPException(status_code=400, detail="Missing cipher_text")

    #  Створюємо об'єкт AES ключа з даних сесії
    aes_key_model = AesKey(key=session.aes_key, iv=session.iv)

    #  Розшифровуємо повідомлення
    decrypted_msg = aes_service.decrypt(aes_key_model, cipher_text)

    #  Формуємо відповідь із поточним часом (UTC)
    reply = f"[{datetime.utcnow().strftime('%H:%M:%S')} UTC] Server received: {decrypted_msg}"

    #  Шифруємо відповідь
    encrypted_reply = aes_service.encrypt(aes_key_model, reply)

    return {"cipher_text": encrypted_reply}
