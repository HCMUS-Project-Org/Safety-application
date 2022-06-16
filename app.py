import os
import authen
from form.authenForm import LoginForm, RegisterForm

try:
    from dotenv import load_dotenv
    from flask import Flask, redirect, render_template, request, url_for
    from flask_bootstrap import Bootstrap
    from pymongo import MongoClient

except:
    os.system("pip install -r requirements.txt")
    # import again
    from dotenv import load_dotenv
    from flask import Flask, redirect, render_template, request, url_for
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

        # check if email exists
        user = db.users.find_one({"email": email})

        if user is None:
            return render_template("login.html", form=form, error="Email does not exist.")

        if authen.verify_password(passwd, user["password"]):
            return redirect(url_for('home'))
        else:
            return render_template("login.html", form=form, error="Password is incorrect.")

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if request.method == "POST":
        passwd = request.form.get("password")
        hash_passwd = authen.salt_hash256(passwd)

        # check if email exists
        if (authen.check_email_exists(request.form.get("email"))):
            return render_template("register.html", form=form, error="Email exist.")

        user = {
            "email": form.email.data,
            "name": form.name.data,
            "phone": form.phone.data,
            "address": form.address.data,
            "password": hash_passwd
        }

        db.users.insert_one(user)
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@ app.route('/home', methods=['GET', 'POST'])
def home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=APP_PORT, threaded=True, debug=True)
