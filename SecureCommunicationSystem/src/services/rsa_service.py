import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))


from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from src.models.rsa_keys import RsaKeys
import base64


class RsaService:
    """Сервіс для генерації ключів, шифрування та дешифрування на базі RSA."""

    def generate_keys(self) -> RsaKeys:
        """Генерує пару ключів RSA (public/private) і повертає модель RsaKeys."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Серіалізація ключів у PEM-формат
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return RsaKeys(
            public_key=public_pem.decode("utf-8"),
            private_key=private_pem.decode("utf-8")
        )

    def encrypt(self, public_key: str, plain_text: str) -> str:
        """Шифрує текст за допомогою публічного ключа RSA, повертає Base64-рядок."""
        public_key_obj = serialization.load_pem_public_key(public_key.encode("utf-8"))
        cipher_bytes = public_key_obj.encrypt(
            plain_text.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(cipher_bytes).decode("utf-8")

    def decrypt(self, private_key: str, cipher_text: str) -> str:
        """Розшифровує Base64-шифротекст за допомогою приватного ключа RSA."""
        private_key_obj = serialization.load_pem_private_key(
            private_key.encode("utf-8"),
            password=None
        )
        decrypted = private_key_obj.decrypt(
            base64.b64decode(cipher_text),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode("utf-8")


if __name__ == "__main__":
    service = RsaService()

    keys = service.generate_keys()
    print("Public Key:\n", keys.public_key)
    print("Private Key:\n", keys.private_key)

    text = "Hello RSA!"
    encrypted = service.encrypt(keys.public_key, text)
    print("\nEncrypted:", encrypted)

    decrypted = service.decrypt(keys.private_key, encrypted)
    print("\nDecrypted:", decrypted)
