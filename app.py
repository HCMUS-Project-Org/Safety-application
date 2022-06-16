import os
from form.authenForm import LoginForm, RegisterForm

try:
    from dotenv import load_dotenv
    from pymongo import MongoClient
    from flask_pymongo import PyMongo
    from wtforms.validators import DataRequired
    from wtforms import StringField, SubmitField
    from flask_wtf import FlaskForm
    from flask_bootstrap import Bootstrap
    from flask import Flask, render_template, redirect, url_for, request
    from base64 import b64encode
    import hashlib
except:
    os.system("pip install -r requirements.txt")
    # import again
    from wtforms.validators import DataRequired
    from wtforms import StringField, SubmitField
    from flask_wtf import FlaskForm
    from flask_bootstrap import Bootstrap
    from flask import Flask, render_template, redirect, url_for
    from flask_bcrypt import Bcrypt

load_dotenv()  # take environment variables from .env.

SALT_LENGTH = int(os.getenv("SALT_LENGTH"))
SECRET_KEY = os.getenv("SECRET_KEY")
MONGO_URI = os.getenv("MONGO_URI")
MONGO_PORT = os.getenv("MONGO_PORT")
APP_PORT = os.getenv("APP_PORT")

app = Flask(__name__)

# salt = b64encode(os.urandom(SALT_LENGTH)).decode('utf-8')
salt = b64encode(os.urandom(SALT_LENGTH)).decode('utf-8')[:SALT_LENGTH]
# Flask-WTF requires an encryption key - the string can be anything
app.config['SECRET_KEY'] = SECRET_KEY
# app.config["MONGO_URI"] = MONGO_URI
# mongo = PyMongo(app)

# mongodb_client = PyMongo(app, uri=MONGO_URI)
# db = mongodb_client.db

# connect to mongoDB
client = MongoClient(MONGO_URI, int(MONGO_PORT))
db = client.myDatabase  # database name

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
        app.logger.info(email + " - " + passwd)
        # check if email exists
        user = db.users.find_one({"email": email})
        app.logger.info(user)
        if user is None:
            return render_template("login.html", form=form, error="Email does not exist.")

        app.logger.info(user["password"])

        user_salt = user["password"][:SALT_LENGTH]
        user_hash_passwd = user["password"][SALT_LENGTH:]

        app.logger.info("user_salt: " + user_salt)
        app.logger.info("user_hash_passwd: " + user_hash_passwd)
        app.logger.info(
            "ccc:" + hashlib.sha256((passwd + user_salt).encode("utf-8")).hexdigest())
        # check if password is correct
        if user_hash_passwd == hashlib.sha256((passwd + user_salt).encode("utf-8")).hexdigest():
            return redirect(url_for('home'))
        else:
            return render_template("login.html", form=form, error="Password is incorrect.")

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if request.method == "POST":
        passwd = request.form.get("password")
        app.logger.info("Registering password: " + passwd)

        app.logger.info("salt:" + salt)
        app.logger.info("pass:" + form.password.data + salt)
        # hash SHA256 + salt
        hash_password = hashlib.sha256(
            (form.password.data + salt).encode("utf-8")).hexdigest()

        app.logger.info("hash:" + hash_password)
        user = {
            "email": form.email.data,
            "name": form.name.data,
            "phone": form.phone.data,
            "address": form.address.data,
            "password": salt + hash_password,
            "salt": salt
        }

        db.users.insert_one(user)
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@ app.route('/home', methods=['GET', 'POST'])
def home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=APP_PORT, threaded=True, debug=True)
