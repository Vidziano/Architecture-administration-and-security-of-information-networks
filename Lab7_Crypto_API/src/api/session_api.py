import base64
from fastapi import APIRouter, HTTPException, Header
from src.services.session_service import SessionService
from src.services.aes_service import AesService
from src.models.aes_key import AesKey
from src.models.session_data import SessionData

router = APIRouter(prefix="/api/session", tags=["Session API"])

# Створюємо сервіс (один екземпляр для всіх запитів)
session_service = SessionService()
aes_service = AesService()


@router.get("/init")
def init_session():
    """Крок 1: Клієнт запитує випадковий публічний ключ."""
    rsa_id, rsa_keys = session_service.get_random_rsa_pair()
    return {"rsa_id": rsa_id, "public_key": rsa_keys.public_key}


@router.post("/handshake")
def handshake(data: dict):
    """Крок 2: Сервер приймає зашифровані AES key + IV."""
    rsa_id = data.get("rsa_id")
    session_id = data.get("session_id")
    encrypted_key = data.get("encrypted_key")
    encrypted_iv = data.get("encrypted_iv")

    if not all([rsa_id, session_id, encrypted_key, encrypted_iv]):
        raise HTTPException(status_code=400, detail="Missing parameters")

    # Дешифруємо RSA-приватним ключем
    rsa_keys = session_service.rsa_pool.get(rsa_id)
    if not rsa_keys:
        raise HTTPException(status_code=404, detail="RSA key not found")

    from src.services.rsa_service import RsaService
    rsa_service = RsaService()

    aes_key_str = rsa_service.decrypt(rsa_keys.private_key, encrypted_key)
    iv_str = rsa_service.decrypt(rsa_keys.private_key, encrypted_iv)

    session_service.save_session(session_id, AesKey(key=aes_key_str, iv=iv_str))
    return {"status": "handshake_successful"}


@router.post("/message")
def message(data: dict, x_session_id: str = Header(...)):
    """Крок 3: Сервер приймає AES-зашифроване повідомлення."""
    session = session_service.get_session(x_session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    cipher_text = data.get("cipher_text")
    if not cipher_text:
        raise HTTPException(status_code=400, detail="Missing cipher_text")

    decrypted_msg = aes_service.decrypt(session, cipher_text)

    from datetime import datetime
    reply = f"[{datetime.now().strftime('%H:%M:%S')}] Server received: {decrypted_msg}"

    encrypted_reply = aes_service.encrypt(session, reply)
    return {"cipher_text": encrypted_reply}
