import base64
from datetime import datetime
from fastapi import APIRouter, HTTPException, Header
from src.services.session_service import SessionService
from src.services.aes_service import AesService
from src.models.aes_key import AesKey
from src.services.rsa_service import RsaService
from dateutil import parser   
from src.services.hash_service import HashService
hash_service = HashService()


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
    перевіряє термін дії сесії, валідує SHA-256 хеш і формує відповідь.
    """
    session = session_service.get_session(x_session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Перевірка терміну дії сесії
    expired_at = session.expired_at
    if isinstance(expired_at, str):
        expired_at = parser.parse(expired_at)
    if expired_at < datetime.utcnow():
        raise HTTPException(status_code=440, detail="Session expired")

    # Перевіряємо наявність даних
    cipher_text = data.get("cipher_text")
    client_hash = data.get("hash")
    if not cipher_text:
        raise HTTPException(status_code=400, detail="Missing cipher_text")
    if not client_hash:
        raise HTTPException(status_code=400, detail="Missing hash")

    # Створюємо AES ключ
    aes_key_model = AesKey(key=session.aes_key, iv=session.iv)

    # Розшифровуємо повідомлення
    decrypted_msg = aes_service.decrypt(aes_key_model, cipher_text)

    # Перевірка цілісності повідомлення через SHA-256
    server_hash = hash_service.sha256(decrypted_msg)
    if client_hash != server_hash:
        raise HTTPException(status_code=400, detail="Data tampered or corrupted")

    # Формуємо відповідь
    reply = f"[{datetime.utcnow().strftime('%H:%M:%S')} UTC] Server received: {decrypted_msg}"

    # Шифруємо відповідь
    encrypted_reply = aes_service.encrypt(aes_key_model, reply)

    return {"cipher_text": encrypted_reply}


@router.get("/sessions")
def get_sessions():
    """
    Повертає всі активні та прострочені сесії.
    """
    return session_service.get_all_sessions()
