from NTC import db, login_manager
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(15), unique = True, nullable=False)
    email = db.Column(db.String(100), unique = True, nullable=False)
    name = db.Column(db.String(35), unique = False, nullable=False)
    key = db.Column(db.String(100000), unique = True, nullable=False)
    password = db.Column(db.String(120), unique = False, nullable=False)
    verified = db.Column(db.String(5), nullable = False)
    authentication = db.Column(db.String(10), nullable = False)

    def __repr__(self):
        return f"User('{self.name}', '{self.username}', '{self.email}')"

class BlockchainDB(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash = db.Column(db.String(800), nullable=False)
    transactions = db.Column(db.String(800), nullable=False)
    time = db.Column(db.String(800), nullable=False)
    prev = db.Column(db.String(800), nullable=False)
    nonce = db.Column(db.String(800), nullable=False)
    hash = db.Column(db.String(800), nullable=False)
    def __init__(self, hash, transaction, time, prev, nonse):
        self.hash = hash
        self.transaction = transaction
        self.time = time
        self.prev = prev
        self.nonce = nonse

class Transactions(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key = True, nullable=False)
    sender = db.Column(db.String(80), nullable=False)
    reciver = db.Column(db.String(80), nullable=False)
    amt = db.Column(db.String(80), nullable=False)
    def __init__(self, sender, reciever, amt):
        self.sender = sender
        self.reciver = reciever
        self.amt = amt

db.create_all ()

@login_manager.user_loader # uloader  for login_manager
def load_user(user_id):
    return User.query.get(int(user_id))