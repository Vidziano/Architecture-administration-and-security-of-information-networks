import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from src.models.aes_key import AesKey


class AesService:
    """Сервіс для генерації ключів і шифрування/дешифрування даних на базі AES."""

    def generate_secret_key(self) -> AesKey:
        """Генерує секретний AES-ключ (256 bit) і IV (128 bit) у Base64."""
        key = os.urandom(32)  # 256 біт
        iv = os.urandom(16)   # 128 біт

        return AesKey(
            key=base64.b64encode(key).decode("utf-8"),
            iv=base64.b64encode(iv).decode("utf-8")
        )

    def encrypt(self, aes_key: AesKey, plain_text: str) -> str:
        """Шифрує текст за допомогою AES (CBC)."""
        key = base64.b64decode(aes_key.key)
        iv = base64.b64decode(aes_key.iv)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(pad(plain_text.encode("utf-8"), AES.block_size))

        return base64.b64encode(encrypted_bytes).decode("utf-8")

    def decrypt(self, aes_key: AesKey, cipher_text: str) -> str:
        """Дешифрує Base64-шифротекст назад у звичайний рядок."""
        key = base64.b64decode(aes_key.key)
        iv = base64.b64decode(aes_key.iv)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(base64.b64decode(cipher_text)), AES.block_size)

        return decrypted_bytes.decode("utf-8")


# Тестовий запуск
if __name__ == "__main__":
    service = AesService()
    aes_key = service.generate_secret_key()

    print("AES Key:", aes_key.key)
    print("AES IV:", aes_key.iv)

    text = "AES encryption test"
    encrypted = service.encrypt(aes_key, text)
    print("\nEncrypted:", encrypted)

    decrypted = service.decrypt(aes_key, encrypted)
    print("Decrypted:", decrypted)
