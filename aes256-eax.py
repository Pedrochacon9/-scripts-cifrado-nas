from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64, os

def generar_guardar_clave():
    password = b"SuperSecretoInterno123"
    salt = os.urandom(16)  # Generamos un salt aleatorio

    # Derivar clave con PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    clave_cifrado = kdf.derive(password)  # Clave de 256 bits

    # Generar clave maestra
    clave_maestra = os.urandom(32)

    # Cifrado con AES-256-EAX
    nonce = os.urandom(16)  # EAX usa un nonce de 16 bytes
    cipher = Cipher(algorithms.AES(clave_cifrado), modes.EAX(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    clave_maestra_cifrada = encryptor.update(clave_maestra) + encryptor.finalize()
    tag = encryptor.tag  # Tag de autenticación de 16 bytes

    # Guardar en un archivo seguro
    with open("clave_maestra_cifrada_eax.key", "wb") as f:
        f.write(salt + nonce + tag + clave_maestra_cifrada)

    print("Clave maestra cifrada con AES-256-EAX y almacenada correctamente.")

if __name__ == "__main__":
    generar_guardar_clave()
