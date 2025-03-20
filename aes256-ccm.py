from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import sys
import time

# IMPORTAMOS la función de recuperación de la clave maestra
from recuperar_clave_maestra import recuperar_clave

# Recuperamos la clave maestra (viene en base64) y la decodificamos
key_base64 = recuperar_clave()
key = base64.urlsafe_b64decode(key_base64)  # Ahora la clave tiene 32 bytes (AES-256)

def cifrar(input_file, output_file):
    nonce = os.urandom(13)  # AES-CCM usa un nonce de 13 bytes
    backend = default_backend()
    
    cipher = Cipher(algorithms.AES(key), modes.CCM(nonce, tag_length=16), backend=backend)
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f:
        data = f.read()

    start = time.time()
    encrypted = encryptor.update(data) + encryptor.finalize()
    end = time.time()

    tag = encryptor.tag  # Tag de autenticación de 16 bytes

    with open(output_file, 'wb') as f:
        f.write(nonce + tag + encrypted)  # Guardamos nonce, tag y datos cifrados

    print(f"CIFRADO AES-256-CCM completado en {end - start:.6f} segundos")

def descifrar(input_file, output_file):
    with open(input_file, 'rb') as f:
        nonce = f.read(13)  # Leemos el nonce de 13 bytes
        tag = f.read(16)  # Leemos la etiqueta de autenticación de 16 bytes
        encrypted = f.read()  # Leemos los datos cifrados

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CCM(nonce, tag), backend=backend)
    decryptor = cipher.decryptor()

    start = time.time()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    end = time.time()

    with open(output_file, 'wb') as f:
        f.write(decrypted)

    print(f"DESCIFRADO AES-256-CCM completado en {end - start:.6f} segundos")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python aes256_ccm.py <cifrar|descifrar> <input_file> <output_file>")
        sys.exit(1)

    operacion = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]

    if operacion == "cifrar":
        cifrar(input_file, output_file)
    elif operacion == "descifrar":
        descifrar(input_file, output_file)
    else:
        print("Operación inválida.")
