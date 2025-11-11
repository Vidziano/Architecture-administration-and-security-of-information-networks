import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import uuid
import random
from typing import Dict
from src.models.session_data import SessionData
from src.models.rsa_keys import RsaKeys
from src.models.aes_key import AesKey
from src.services.rsa_service import RsaService
from datetime import datetime, timedelta

SESSION_DURATION_MINUTES = 1  # тривалість сесії у хвилинах


class SessionService:
    """Сервіс для керування RSA-парами та AES-сесіями."""

    def __init__(self):
        self.rsa_pool: Dict[str, RsaKeys] = {}
        self.sessions: Dict[str, SessionData] = {}
        self.rsa_service = RsaService()

        for _ in range(10):
            rsa_id = str(uuid.uuid4())
            self.rsa_pool[rsa_id] = self.rsa_service.generate_keys()
        print(f" Ініціалізовано {len(self.rsa_pool)} RSA-пар ключів")

    def get_random_rsa_pair(self) -> tuple[str, RsaKeys]:
        """Повертає випадкову RSA-пару (id, keys)."""
        if not self.rsa_pool:
            for _ in range(10):
                rsa_id = str(uuid.uuid4())
                self.rsa_pool[rsa_id] = self.rsa_service.generate_keys()
        rsa_id = random.choice(list(self.rsa_pool.keys()))
        return rsa_id, self.rsa_pool[rsa_id]

    def save_session(self, session_id: str, aes_key: AesKey):
        """Зберігає AES-ключ у сесійному сховищі з терміном дії."""
        expired_at = datetime.utcnow() + timedelta(minutes=SESSION_DURATION_MINUTES)
        session = SessionData(
            session_id=session_id,
            aes_key=aes_key.key,
            iv=aes_key.iv,
            expired_at=expired_at
        )
        self.sessions[session_id] = session

    def get_session(self, session_id: str) -> SessionData | None:
        """Повертає сесію, якщо вона існує."""
        return self.sessions.get(session_id)
