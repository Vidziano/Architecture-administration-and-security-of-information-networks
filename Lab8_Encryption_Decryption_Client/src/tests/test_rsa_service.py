from src.services.rsa_service import RsaService

def test_encrypt_and_decrypt():
    service = RsaService()
    keys = service.generate_keys()
    text = "RSA unit test"

    encrypted = service.encrypt(keys.public_key, text)
    decrypted = service.decrypt(keys.private_key, encrypted)

    assert decrypted == text
