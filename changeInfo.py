import cryptography
import app


def change_info(new_info, current_info):
    # change password

    # update user
    app.db.users.update_one(
        {"email": current_info["email"]},
        {"$set": new_info}
    )


def change_passwd(old_passphrase, new_passphrase):
    pass
