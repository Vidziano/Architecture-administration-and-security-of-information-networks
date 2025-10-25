import requests
import uuid
import sys, os

# Додаємо шлях до кореня проєкту
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.services.aes_service import AesService
from src.services.rsa_service import RsaService
from src.models.aes_key import AesKey

# === Базова адреса до нашого FastAPI сервера ===
API_BASE = "http://127.0.0.1:8000/api/session"

# === Ініціалізація сервісів ===
aes_service = AesService()
rsa_service = RsaService()


def get_public_key():
    """Отримати випадковий публічний ключ від сервера."""
    resp = requests.get(f"{API_BASE}/init")
    data = resp.json()
    rsa_id = data["rsa_id"]
    public_key = data["public_key"]
    print(f"✅ Отримано RSA ключ із id: {rsa_id[:8]}...")
    return rsa_id, public_key


def perform_handshake(rsa_id, public_key, aes_key, session_id):
    """Виконати handshake — передати AES ключ та IV, зашифровані RSA."""
    encrypted_key = rsa_service.encrypt(public_key, aes_key.key)
    encrypted_iv = rsa_service.encrypt(public_key, aes_key.iv)

    payload = {
        "rsa_id": rsa_id,
        "session_id": session_id,
        "encrypted_key": encrypted_key,
        "encrypted_iv": encrypted_iv,
    }

    resp = requests.post(f"{API_BASE}/handshake", json=payload)
    print("🤝 Handshake:", resp.json())


def send_encrypted_message(session_id, aes_key, message):
    """Шифрує повідомлення, відправляє його на сервер і виводить відповідь."""
    cipher_text = aes_service.encrypt(aes_key, message)
    headers = {"x-session-id": session_id}
    body = {"cipher_text": cipher_text}

    resp = requests.post(f"{API_BASE}/message", json=body, headers=headers)
    data = resp.json()

    decrypted = aes_service.decrypt(aes_key, data["cipher_text"])
    print(f"📩 Відповідь сервера:\n{decrypted}\n")


def main():
    print("🔒 Secure Console Client Started")

    # 1. Отримати публічний ключ
    rsa_id, public_key = get_public_key()

    # 2. Згенерувати AES ключ і session_id
    aes_key = aes_service.generate_secret_key()
    session_id = str(uuid.uuid4())

    # 3. Виконати handshake
    perform_handshake(rsa_id, public_key, aes_key, session_id)

    # 4. Головний цикл для введення повідомлень
    while True:
        msg = input("Введіть повідомлення ('exit' для виходу): ")
        if msg.lower() == "exit":
            print("👋 Завершення сесії.")
            break
        send_encrypted_message(session_id, aes_key, msg)


# === Точка входу ===
if __name__ == "__main__":
    main()
