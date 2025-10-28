from src.services.aes_service import AesService

def test_encrypt_and_decrypt():
    """Перевіряє коректність шифрування і дешифрування AES."""
    # Arrange
    service = AesService()
    aes_key = service.generate_secret_key()
    original_text = "AES unit test"

    # Act
    encrypted = service.encrypt(aes_key, original_text)
    decrypted = service.decrypt(aes_key, encrypted)

    # Assert
    assert decrypted == original_text
