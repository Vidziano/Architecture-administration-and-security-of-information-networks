import uuid
import random
from typing import Dict
from src.models.session_data import SessionData
from src.models.rsa_keys import RsaKeys
from src.models.aes_key import AesKey
from src.services.rsa_service import RsaService

class SessionService:
    """Сервіс для керування RSA-парами та AES-сесіями."""

    def __init__(self):
        self.rsa_pool: Dict[str, RsaKeys] = {}
        self.sessions: Dict[str, AesKey] = {}
        self.rsa_service = RsaService()

        # Створюємо 10 RSA-пар при запуску
        for _ in range(10):
            rsa_id = str(uuid.uuid4())
            self.rsa_pool[rsa_id] = self.rsa_service.generate_keys()
        print(f"🔐 Ініціалізовано {len(self.rsa_pool)} RSA-пар ключів")

    def get_random_rsa_pair(self) -> tuple[str, RsaKeys]:
        """Повертає випадкову RSA-пару (id, keys)."""
        rsa_id = random.choice(list(self.rsa_pool.keys()))
        return rsa_id, self.rsa_pool[rsa_id]

    def save_session(self, session_id: str, aes_key: AesKey):
        """Зберігає AES-ключ у сесійному сховищі."""
        self.sessions[session_id] = aes_key

    def get_session(self, session_id: str) -> AesKey:
        """Повертає AES-ключ для конкретної сесії."""
        return self.sessions.get(session_id)
