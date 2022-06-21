import cryptography
import app
import authen
import json
from flask import session


def change_info(new_info, current_info):
    if new_info["passphase"] != "":
        # change password
        new_passphase = authen.salt_hash256(new_info["passphase"])

        # change Private_key to ensure Integrity
        origin_priv_key = cryptography.AES_decrypt(
            current_info["private_key"], current_info["passphase"])

        new_priv_key = cryptography.AES_encrypt(origin_priv_key, new_passphase)

        # update new info
        new_info["pass"] = new_info["passphase"]
        new_info["passphase"] = new_passphase
        new_info["private_key"] = new_priv_key
    else:
        new_info["passphase"] = current_info["passphase"]

    new_info["avatar"] = current_info["avatar"]

    # update user
    app.db.users.update_one(
        {"email": current_info["email"]},
        {"$set": new_info}
    )

    session["user"] = json.dumps(new_info, default=str)


# TODO: feature: change avatar
