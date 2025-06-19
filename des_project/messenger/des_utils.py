from pyDes import des, CBC, PAD_PKCS5
import base64
import os

def encrypt_des(text, key_bytes):
    des_obj = des(key_bytes, CBC, b"\0\0\0\0\0\0\0\0", padmode=PAD_PKCS5)
    encrypted = des_obj.encrypt(text.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_des(cipher_text, key_bytes):
    des_obj = des(key_bytes, CBC, b"\0\0\0\0\0\0\0\0", padmode=PAD_PKCS5)
    decrypted = des_obj.decrypt(base64.b64decode(cipher_text))
    return decrypted.decode()
