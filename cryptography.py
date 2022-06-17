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
    pub_key_pem = key.publickey().exportKey().decode()
    priv_key_pem = key.exportKey().decode()
    return pub_key_pem, priv_key_pem


def RSA_encrypt(plain_text, pub_key_pem):
    public_key = RSA.importKey(pub_key_pem)
    public_key = RSA.construct((public_key.n, public_key.e))

    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(plain_text.encode("utf-8"))

    return encrypted


def RSA_decrypt(cipher_text, priv_key_pem):
    private_key = RSA.importKey(priv_key_pem)
    private_key = RSA.construct((private_key.n, private_key.e, private_key.d))

    decryptor = PKCS1_OAEP.new(private_key)
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


def gen_user_RSA_key_pem(passphrase):
    pub_key_pem, priv_key_pem = gen_RSA_key_pem()

    encrypted_priv_key = AES_encrypt(priv_key_pem, passphrase)

    return pub_key_pem, encrypted_priv_key


if __name__ == "__main__":
    # get RSA pair key PEM
    publickeyPEM, privatekeyPEM = gen_RSA_key_pem()

    # encrypt Priv_ley_PEM with AES
    encrypted_priv_key = AES_encrypt(privatekeyPEM, "my password")

    # decrypt Priv_ley_PEM with AES
    decrypted_priv_key = AES_decrypt(encrypted_priv_key, "my password")

    print("decrypted_priv_key", decrypted_priv_key)
    mess = "encrypt RSA private key"

    # encrypt Priv_ley_PEM with RSA
    cipher_text = RSA_encrypt(mess, publickeyPEM)

    try:
        # decrypt Priv_ley_PEM with RSA
        plain_text = RSA_decrypt(cipher_text, decrypted_priv_key)
        print("plain text:", plain_text)
    except:
        print("decrypt RSA private key failed")
