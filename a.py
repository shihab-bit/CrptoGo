import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random


def encrypt(keyStr, text):
    private_key = hashlib.sha256(keyStr.encode()).digest()
    rem = len(text) % 16
    padded = str.encode(text) + (b'\0' * (16 - rem)) if rem > 0 else str.encode(text)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CFB, iv, segment_size=128)
    enc = cipher.encrypt(padded)[:len(text)]
    return base64.b64encode(iv + enc).decode()


def decrypt(keyStr, text):
    private_key = hashlib.sha256(keyStr.encode()).digest()
    text = base64.b64decode(text)
    iv, value = text[:16], text[16:]
    rem = len(value) % 16
    padded = value + (b'\0' * (16 - rem)) if rem > 0 else value
    cipher = AES.new(private_key, AES.MODE_CFB, iv, segment_size=128)
    return (cipher.decrypt(padded)[:len(value)]).decode()


def main():
    key =input("enter key:")
    text=input("enter msg:")
    encrypted=encrypt(key, text)
    print(encrypted)

    print(decrypt(key, encrypted))

if __name__== '__main__':
    main()
