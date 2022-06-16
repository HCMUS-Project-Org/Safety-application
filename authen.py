import hashlib
from base64 import b64encode
from os import getenv, urandom
from dotenv import load_dotenv
from app import db

load_dotenv()  # take environment variables from .env.

SALT_LENGTH = int(getenv("SALT_LENGTH"))

salt = b64encode(urandom(SALT_LENGTH)).decode('utf-8')[:SALT_LENGTH]


def check_email_exists(email):
    user = db.users.find_one({"email": email})
    if user is None:  # not exist
        return False
    return True


def salt_hash256(passwd):
    """ 
    salt = random(32 byte)
    hash_pass = hash(passwd + salt)
    storage: passwd = salt + hash_pass

    Return: passwd
    """

    hash_password = hashlib.sha256(
        (passwd + salt).encode("utf-8")).hexdigest()

    return salt + hash_password


def verify_password(passwd, user_passwd):
    user_salt = user_passwd[:SALT_LENGTH]
    user_hash_passwd = user_passwd[SALT_LENGTH:]

    if user_hash_passwd == hashlib.sha256((passwd + user_salt).encode("utf-8")).hexdigest():
        return True
    return False
