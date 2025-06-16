from pyDes import des, CBC, PAD_PKCS5
import base64

def encrypt_des(text, key):
    key = key[:8].ljust(8, ' ')
    des_obj = des(key.encode(), CBC, b"\0\0\0\0\0\0\0\0", padmode=PAD_PKCS5)
    return base64.b64encode(des_obj.encrypt(text.encode())).decode()

def decrypt_des(cipher_text, key):
    key = key[:8].ljust(8, ' ')
    des_obj = des(key.encode(), CBC, b"\0\0\0\0\0\0\0\0", padmode=PAD_PKCS5)
    return des_obj.decrypt(base64.b64decode(cipher_text)).decode()
