import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

BLOCK_SIZE = 16


def pad(s):
    return s + (BLOCK_SIZE - len(s) %
                BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def gen_RSA_key_pem():
    key = RSA.generate(2048)
    return key


def RSA_encrypt(plain_text, pub_key):
    encryptor = PKCS1_OAEP.new(pub_key)
    encrypted = encryptor.encrypt(plain_text.encode("utf-8"))

    return encrypted


def RSA_decrypt(cipher_text, key_pair):
    decryptor = PKCS1_OAEP.new(key_pair)
    decrypted = decryptor.decrypt(cipher_text).decode("utf-8")

    return decrypted


def AES_encrypt(plain_text, passphrase):
    private_key = hashlib.sha256(passphrase.encode("utf-8")).digest()
    plain_text = pad(plain_text).encode("utf-8")
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(plain_text))


def AES_decrypt(cipher_text, passphrase):
    private_key = hashlib.sha256(passphrase.encode("utf-8")).digest()
    cipher_text = base64.b64decode(cipher_text)
    iv = cipher_text[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_text[16:]))


if __name__ == "__main__":
    # test RSA
    key = gen_RSA_key_pem()

    # privatekey = RSA.importKey(privatekeyPEM)
    # publickey = RSA.importKey(publickeyPEM)

    # print("RSA private key: ")
    # print("  n =", privatekey.n)
    # print("  d =", privatekey.d)

    # print("\nRSA public key: ")
    # print("  n =", publickey.n)
    # print("  e =", publickey.e)
    mess = "encrypt me"
    publickey = key.publickey()
    # privateKey = key.key
    cipher_text = RSA_encrypt(mess, publickey)
    plain_text = RSA_decrypt(cipher_text, key)
    print("cipher text:", cipher_text)
    print("plain text:", plain_text)

    print("-------------------------")

    # test AES
    encrypted = AES_encrypt("This is a secret message", "my password")
    decrypted = AES_decrypt(encrypted, "my password")

    print("AES encrypt: {}".format(encrypted))
    print("AES decrypt: {}".format(bytes.decode(decrypted)))
