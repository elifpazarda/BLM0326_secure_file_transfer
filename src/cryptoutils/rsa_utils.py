from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keys(key_size=2048):
    """
    RSA anahtar çifti üretir.
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_key_with_rsa(public_key_bytes, aes_key_bytes):
    """
    RSA public key kullanarak AES anahtarını şifreler.
    """
    public_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key_bytes)
    return encrypted_key

def decrypt_key_with_rsa(private_key_bytes, encrypted_key):
    """
    RSA private key ile şifreli AES anahtarını çözer.
    """
    private_key = RSA.import_key(private_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)
    return decrypted_key

# Test amaçlı örnek kullanım
if __name__ == "__main__":
    aes_key = b"mysecretkey12345"  # 16 byte AES anahtarı (örnek)

    priv, pub = generate_rsa_keys()
    enc = encrypt_key_with_rsa(pub, aes_key)
    dec = decrypt_key_with_rsa(priv, enc)

    print("Orijinal AES Key:", aes_key)
    print("Çözümlenmiş AES Key:", dec)
