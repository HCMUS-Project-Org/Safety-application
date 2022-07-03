import os

try:
    from form.authenForm import LoginForm, RegisterForm
    from form.changeInfoForm import ChangeInfoForm
    from form.uploadFileForm import UploadFileForm
    from Crypto.PublicKey import RSA
    from werkzeug.utils import secure_filename
    import authen
    import cryptography
    import changeInfo
    from dotenv import load_dotenv
    from flask import Flask, redirect, render_template, request, url_for, session
    import json
    from flask_bootstrap import Bootstrap
    from pymongo import MongoClient

except:
    os.system("pip install -r requirements.txt")
