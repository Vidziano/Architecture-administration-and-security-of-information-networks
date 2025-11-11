import hashlib

class HashService:
    """Сервіс для обчислення SHA-256 хешів."""

    @staticmethod
    def sha256(data: str) -> str:
        """Обчислює SHA-256 від вхідного тексту та повертає hex-рядок."""
        if not isinstance(data, str):
            raise TypeError("Data must be a string")
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
