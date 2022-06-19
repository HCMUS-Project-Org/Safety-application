import os
import authen
import cryptography
from form.authenForm import LoginForm, RegisterForm
from form.changeInfoForm import ChangeInfoForm
from form.uploadFileForm import UploadFileForm
import changeInfo

try:
    from dotenv import load_dotenv
    from flask import Flask, redirect, render_template, request, url_for, session
    import json
    from flask_bootstrap import Bootstrap
    from pymongo import MongoClient

except:
    os.system("pip install -r requirements.txt")
    # import again
    from dotenv import load_dotenv
    from flask import Flask, redirect, render_template, request, url_for, session
    import json
    from flask_bootstrap import Bootstrap
    from pymongo import MongoClient

load_dotenv()  # take environment variables from .env.

SALT_LENGTH = int(os.getenv("SALT_LENGTH"))
SECRET_KEY = os.getenv("SECRET_KEY")
MONGO_URI = os.getenv("MONGO_URI")
MONGO_PORT = os.getenv("MONGO_PORT")
APP_PORT = os.getenv("APP_PORT")

app = Flask(__name__)

# Flask-WTF requires an encryption key - the string can be anything
app.config['SECRET_KEY'] = SECRET_KEY
# connect to mongoDB
try:
    client = MongoClient(MONGO_URI, int(MONGO_PORT))
    db = client.myDatabase  # database name
except:
    app.logger.error("Can not connect MongoDB")

Bootstrap(app)


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == "POST":
        email = request.form.get("email")
        passwd = request.form.get("password")

        # check if email exists
        user = db.users.find_one({"email": email})

        if user is None:
            return render_template("login.html", form=form, error="Email does not exist.")

        if authen.verify_password(passwd, user["passphase"]):

            user = json.dumps(user, default=str)
            session["user"] = user
            return redirect(url_for('home'))
        else:
            return render_template("login.html", form=form, error="Password is incorrect.")

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if request.method == "POST":
        passwd = request.form.get("password")
        passphase = authen.salt_hash256(passwd)

        # check if email exists
        if (authen.check_email_exists(request.form.get("email"))):
            return render_template("register.html", form=form, error="Email exist.")

        public_key, private_key = cryptography.gen_user_RSA_key_pem(
            passphase)

        user = {
            "email": form.email.data,
            "name": form.name.data,
            "phone": form.phone.data,
            "address": form.address.data,
            "passphase": passphase,
            "pass": passwd,  # temp
            "public_key": public_key,
            "private_key": private_key,
        }

        db.users.insert_one(user)

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@ app.route('/home', methods=['GET', 'POST'])
def home():
    # authorize user
    if not 'user' in session:
        return redirect(url_for('login'))

    user = json.loads(session["user"])
    form = ChangeInfoForm()
    upload_form = UploadFileForm()

    # # test
    # cipher_text = cryptography.RSA_encrypt(
    #     "hello sssd", user["public_key"])

    # try:
    #     # decrypt Priv_ley_PEM with RSA
    #     user["private_key"] = cryptography.AES_decrypt(
    #         user["private_key"], user["passphase"])
    #     plain_text = cryptography.RSA_decrypt(cipher_text, user["private_key"])
    #     print("plain text:", plain_text)
    # except:
    #     print("decrypt RSA private key failed")

    # change user infotmation
    if request.method == "POST":
        new_info = {
            "email": request.form.get("email"),
            "name": request.form.get("name"),
            "phone": request.form.get("phone"),
            "address": request.form.get("address"),
            "passphase": request.form.get("password")
        }

        app.logger.info("----- CHANGE INFO --------")
        app.logger.info("new info: %s", new_info)

        changeInfo.change_info(new_info, user)

    return render_template('home.html', form=form, upload_form=upload_form, user=user)


@app.route('/upload')
def upload_file():
    pass


@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=APP_PORT, threaded=True, debug=True)
