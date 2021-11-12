from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import os
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from flask_qrcode import *
import hashlib
import json
from time import time
import stripe
import qrcode
from flask_mail import Message
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt

from NTC.blockchain import *

app = Flask(__name__)
csrf = CSRFProtect(app)
csrf.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ntcoin.db'
app.config['SECRET_KEY']  = os.urandom(24)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
MAIL_USERNAME = 'danielrojas@ntechstorm.com'
MAIL_PASSWORD = '7443614a'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "stronk"
login_serializer = URLSafeTimedSerializer(app.secret_key)
qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=5)
stripe_keys = {
  'secret_key': 'sk_test_51HwsnwFqMlvMMS7XHrEwAWq7HyYiigagqksoTxfsUHjqkcQYm4blVvd7e7Ib1r029I50xvwmq6qJUszHYfvVp3j000fiH31L2r',
  'publishable_key': 'pk_test_51HwsnwFqMlvMMS7XXZWEcpTHERnRlS9qFN9LAnlSbAQ6V0bMRkMeRkD02n1qTdBsl1YcFr3sGVZgsHawnlSLSgSm00ydPlsByI'
}
stripe.api_key = stripe_keys['secret_key']
blockchainObj = Blockchain()
bcrypt = Bcrypt(app)

from NTC import routes
db.create_all()