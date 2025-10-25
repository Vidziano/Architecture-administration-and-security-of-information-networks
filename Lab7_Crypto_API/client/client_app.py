import sys
import os

# === Додати шлях до кореня проєкту ===
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests
import uuid
import datetime
from src.services.aes_service import AesService
from src.services.rsa_service import RsaService
from src.models.aes_key import AesKey

API_BASE = "http://127.0.0.1:8000/api/session"

aes_service = AesService()
rsa_service = RsaService()

LOG_FILE = "client/client_log.txt"


def log_event(text: str):
    """Записує події клієнта у client_log.txt."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {text}\n")


def get_public_key():
    """Отримати випадковий публічний ключ від сервера."""
    resp = requests.get(f"{API_BASE}/init")
    data = resp.json()
    rsa_id = data["rsa_id"]
    public_key = data["public_key"]
    print(f"✅ Отримано RSA ключ із id: {rsa_id[:8]}...")
    log_event(f"Отримано RSA ключ із id: {rsa_id}")
    return rsa_id, public_key


def perform_handshake(rsa_id, public_key, aes_key, session_id):
    """Виконати handshake — передати AES ключ та IV через заголовки."""
    encrypted_key = rsa_service.encrypt(public_key, aes_key.key)
    encrypted_iv = rsa_service.encrypt(public_key, aes_key.iv)

    headers = {
        "x-rsa-id": rsa_id,
        "x-session-id": session_id,
    }

    payload = {
        "encrypted_key": encrypted_key,
        "encrypted_iv": encrypted_iv,
    }

    resp = requests.post(f"{API_BASE}/handshake", json=payload, headers=headers)
    result = resp.json()
    print("🤝 Handshake:", result)
    log_event(f"Handshake established: {result}")


def send_encrypted_message(session_id, aes_key, message):
    """Шифрує повідомлення, надсилає його на сервер і виводить відповідь."""
    cipher_text = aes_service.encrypt(aes_key, message)
    headers = {"x-session-id": session_id}
    body = {"cipher_text": cipher_text}

    resp = requests.post(f"{API_BASE}/message", json=body, headers=headers)
    data = resp.json()

    decrypted = aes_service.decrypt(aes_key, data["cipher_text"])
    print(f"📩 Відповідь сервера:\n{decrypted}\n")

    # Запис у лог
    log_event(f"Client: {message}")
    log_event(f"Server: {decrypted}")


def main():
    print("🔒 Secure Console Client Started")

    # 1️ Отримати публічний ключ
    rsa_id, public_key = get_public_key()

    # 2️ Згенерувати AES ключ і session_id
    aes_key = aes_service.generate_secret_key()
    session_id = str(uuid.uuid4())

    # 3️ Виконати handshake
    perform_handshake(rsa_id, public_key, aes_key, session_id)

    # 4️ Основний цикл комунікації
    while True:
        msg = input("Введіть повідомлення ('exit' для виходу): ")
        if msg.lower() == "exit":
            print("👋 Завершення сесії.")
            log_event("Сесію завершено користувачем.\n")
            break
        send_encrypted_message(session_id, aes_key, msg)


if __name__ == "__main__":
    main()
