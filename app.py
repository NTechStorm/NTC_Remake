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
QRcode(app)
stripe_keys = {
  'secret_key': 'sk_test_51HwsnwFqMlvMMS7XHrEwAWq7HyYiigagqksoTxfsUHjqkcQYm4blVvd7e7Ib1r029I50xvwmq6qJUszHYfvVp3j000fiH31L2r',
  'publishable_key': 'pk_test_51HwsnwFqMlvMMS7XXZWEcpTHERnRlS9qFN9LAnlSbAQ6V0bMRkMeRkD02n1qTdBsl1YcFr3sGVZgsHawnlSLSgSm00ydPlsByI'
}
stripe.api_key = stripe_keys['secret_key']

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable = False)
    key = db.Column(db.String(120), unique=True, nullable = False)
    password = db.Column(db.String(120), nullable = False)
    coins = db.Column(db.Integer(), nullable=False)
    verified = db.Column(db.String(5), nullable = False)

    def __init__(self, username, email, name, key, password, coins, verified):
        self.username = username
        self.email = email
        self.name = name
        self.key = key
        self.password = password
        self.coins = coins
        self.verified = verified

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

class Blockchain (object):

	def __init__(self):
		self.chain = [self.addGenesisBlock()];
		self.pendingTransactions = [];
		self.difficulty = 1;
		self.minerRewards = 0;
		self.blockSize = 10;

	def mine(self,miner):
		
		lenPT = len(self.pendingTransactions);
		if(lenPT == 1):
			for i in range(0, lenPT, self.blockSize):

				end = i + self.blockSize;
				if i >= lenPT:
					end = lenPT;
				
				transactionSlice = self.pendingTransactions[i:end];

				newBlock = Block(transactionSlice, time());
				newBlock.prev = self.getLastBlock().hash;
				newBlock.mineBlock(self.difficulty);
				self.chain.append(newBlock);
			print("Mining Transactions Success!");

			payMiner = Transaction("Miner Rewards", miner, self.minerRewards);
			self.pendingTransactions = [payMiner];

	def addTransaction(self, sender, reciever, amt):
		if not sender or not reciever or not amt:
			print("transaction error 1");
			return False;
		fee = int(amt)*0.02
		feedamt = int(amt)-int(fee)
		transactionfee = Transaction(reciever, 'Admin', fee)
		transaction = Transaction(sender, reciever, feedamt);
		transaction_ = Transactions(sender, reciever, feedamt)
		db.session.add(transaction_)
		db.session.commit()

		if not transaction.isValidTransaction():
			print("transaction error 2");
			return False;
		self.pendingTransactions.append(transaction);
		self.pendingTransactions.append(transactionfee);
		Blockchain.mine(self, 'Admin')
		return len(self.chain) + 1;

	def getLastBlock(self):
		return self.chain[-1];

	def addGenesisBlock(self):
		t = [];
		t.append(Transaction("me", "you", 10));
		genesis = Block(t, "5");
		return genesis;

	def isValidChain(self):
		for i in range(1, len(self.chain)):
			b1 = self.chain[i-1];
			b2 = self.chain[i];

			if not b2.hasValidTransactions():
				print("error 3");
				return False;

			if b2.hash != b2.calculateHash():
				print("error 4");
				return False;


			if b2.prev != b1.hash:
				print('error 5')
				return False;
		return True;

class Block (object):
	def __init__(self, transactions, time):
		self.transactions = transactions;
		self.time = time;
		self.prev = '';
		self.nonse = 0;
		self.hash = self.calculateHash();

	def calculateHash(self):
		hash_string = str(self.time) + str(self.transactions) +  self.prev + str(self.nonse);
		hash_encoded = json.dumps(hash_string, sort_keys=True).encode();
		return hashlib.sha256(hash_encoded).hexdigest();

	def mineBlock(self, difficulty):
		arr = [];
		for i in range(0, difficulty):
			arr.append(i);
		
		#compute until the beginning of the hash = 0123..difficulty
		arrStr = map(str, arr);  
		hashPuzzle = ''.join(arrStr);
		#print(len(hashPuzzle));
		while self.hash[0:difficulty] != hashPuzzle:
			self.nonse += 1;
			self.hash = self.calculateHash();
			#print(len(hashPuzzle));
			#print(self.hash[0:difficulty]);
		print("Block Mined!");

	def hasValidTransactions(self):
		for i in range(0, len(self.transactions)):
			if not self.transactions[i].isValidTransaction():
				return False;
			return True;

class Transaction (object):
	def __init__(self, sender, reciever, amt):
		self.sender = sender;
		self.reciever = reciever;
		self.amt = amt;
		self.time = time(); #change to current date
		self.hash = self.calculateHash();


	def calculateHash(self):
		hash_string = self.sender + self.reciever + str(self.amt) + str(self.time);
		hash_encoded = json.dumps(hash_string, sort_keys=True).encode();
		return hashlib.sha256(hash_encoded).hexdigest();

	def isValidTransaction(self):
		if(self.hash != self.calculateHash()):
			return False;
		if(self.sender == self.reciever):
			return False;
		return True;
		#needs work!

	#need to implement signing

def send_mail_flask(to,subject,template,**kwargs):
    msg = Message(subject=subject,sender=MAIL_USERNAME, recipients=to)
    msg.body = render_template(template+'.txt', **kwargs)
    msg.html = render_template(template+'.html', **kwargs)
    mail.send(msg)

blockchain = Blockchain()

@login_manager.user_loader # uloader  for login_manager
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/basictransaction', methods = ['GET', 'POST'])
def basictransaction():
    if current_user.is_authenticated:
        if current_user.verified == 'False':
            flash('Get verified to use the site.')
            return redirect(url_for('verify'))
        else:
            if request.method == 'POST':
                reciver = request.form['reciver']
                amt = request.form['amt']
                password = request.form['password']
                fee = int(amt)*0.02
                feedamt = int(amt)-int(fee)
                if check_password_hash(current_user.password, password):
                    if int(current_user.coins) >= int(amt):
                        reciverdb = User.query.filter_by(username = reciver).first()
                        if reciverdb == None:
                            flash('Unable to find username')
                            return redirect(url_for('basictransaction'))
                        else:
                            blockchain.addTransaction(current_user.username, reciver, amt)
                            user = User.query.filter_by(username = current_user.username).first()
                            user.coins = int(user.coins) - int(feedamt)
                            reciverdb.coins = int(reciverdb.coins) + int(feedamt)
                            db.session.commit()
                            flash('Sucsessfuly transfered '+ str(feedamt) +' coins to '+ reciverdb.username)
                            return redirect(url_for('basictransaction'))
                    else:
                        flash('Unsufficent coin amount')
                        return redirect(url_for('basictransaction'))
                else:
                    flash('Unable to verify password')
                    return redirect(url_for('basictransaction'))
            return render_template('basictransaction.html')
    else:
        flash("Please Login")
        return redirect(url_for('login'))

@app.route('/customtransaction/<buyer>', methods = ['GET', 'POST'])
def customtransaction(buyer):
    if current_user.is_authenticated:
        if current_user.verified == 'False':
            flash('Get verified to use the site.')
            return redirect(url_for('verify'))
        else:
            if request.method == 'POST':
                reciver = buyer
                amt = request.form['amt']
                password = request.form['password']
                fee = int(amt)*0.02
                feedamt = int(amt)-int(fee)
                recieverdb = User.query.filter_by(username = reciver).first()
                if check_password_hash(recieverdb.password, password):
                    if int(recieverdb.coins) >= int(amt):
                        if recieverdb == None:
                            flash('Unable to find username')
                            return redirect(buyer)
                        else:
                            blockchain.addTransaction(recieverdb.username, current_user.username, amt)
                            user = User.query.filter_by(username = current_user.username).first()
                            recieverdb.coins = int(recieverdb.coins) - int(feedamt)
                            user.coins = int(user.coins) + int(feedamt)
                            db.session.commit()
                            flash('Sucsessfuly transfered '+ str(feedamt) +' coins to '+ current_user.username)
                            return redirect(buyer)
                    else:
                        flash('Unsufficent coin amount')
                        return redirect(buyer)
                else:
                    flash('Unable to verify password')
                    return redirect(buyer)
            return render_template('customtransaction.html', buyer = buyer)
    else:
        flash("Please Login")
        return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if current_user.is_authenticated:
        customtranslink = qrcode.make('http://192.168.0.102:5000/customtransaction/' + str(current_user.username))
        customtranslink.save('static/qr/'+str(current_user.id)+'.jpg')
        return render_template('profile.html', user = current_user, link = customtranslink)
    else:
        return redirect(url_for('login'))

@app.route('/editprofile')
def editprofile():
    if current_user.is_authenticated:
        user = current_user
        if request.method == 'POST':
            return render_template('editprofile.html', user = user)
        return render_template('editprofile.html', user = user)
    else:
        return redirect(url_for('login'))

@app.route('/yourtransactions')
def yourtransactions():
    if current_user.is_authenticated:
        if current_user.verified == 'False':
            flash('Get verified to use the site.')
            return redirect(url_for('verify'))
        else:
            recived = Transactions.query.filter_by(reciver = current_user.username).all()
            sent = Transactions.query.filter_by(sender = current_user.username).all()
            return render_template('yourtransactions.html', recived = recived, sent = sent)
    else:
        return redirect(url_for('login'))

@app.route('/buycoins')
def buy():
    if current_user.is_authenticated:
        if current_user.verified == 'False':
            flash('Get verified to use the site.')
            return redirect(url_for('verify'))
        else:
            return render_template('buycoins.html', key=stripe_keys['publishable_key'])
    else:
        flash("Please Login")
        return redirect(url_for('login'))

@app.route('/checkout', methods=['POST'])
def checkout():
    if current_user.is_authenticated:
        if current_user.verified == 'False':
            flash('Get verified to use the site.')
            return redirect(url_for('verify'))
        else:
            amount = int(request.form["amount"])*100
            coinamount = int(request.form['amount'])


            customer = stripe.Customer.create(
                email='sample@customer.com',
                source=request.form['stripeToken']
            )

            stripe.Charge.create(
                customer=customer.id,
                amount=amount,
                currency='usd',
                description='Flask Charge'
            )
            Blockchain.addTransaction(Blockchain(), 'Admin', current_user.username, coinamount)
            user = User.query.filter_by(username = current_user.username).first()
            user.coins = int(user.coins) + coinamount
            db.session.commit()
            flash('Thanks! You bought '+ str(coinamount) + ' coins!')
            return redirect(url_for('buy'))
    else:
        flash('HOW THE HECK DID YOU DO THAT HAHA. Oh well, you still need to log in.')
        return redirect(url_for('login'))

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=str(email)).first()
        if not (user):
            flash('Invalid Email')
            return render_template('login.html')
        else:
            if user and check_password_hash(user.password, password):
                login_user(load_user(user.id))
                cuserid = current_user.id
                person = User.query.filter_by(id = cuserid).first()
                flash('Signed in sucsessfuly')
                return redirect(url_for('profile'))
            else:
                flash('Invalid Password')
                return render_template('login.html')
    return render_template('login.html')

@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        emailtest = User.query.filter_by(email = email).first()
        if emailtest == None:
            try:
                key = os.urandom(120)
                user = User(username, email, name, key, generate_password_hash(password), 100, 'False')
                db.session.add(user)
                db.session.commit()
                login_user(load_user(user.id))
                # send_mail_flask(email, 'Verify your account', 'email_temp.html')
                flash('You have signed up. Please check your email to verify.')
                return redirect(url_for('profile'))
            except:
                flash('An error occurred while trying to save your user to the database. Try again.')
        else:
            flash('Email already in database. Please try diffrent email, or log in.')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/logout', methods = ['GET', 'POST'])
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash('Logged Out Sucsessfuly')
        return redirect(url_for('index'))
    else:
        flash("Please Login if you Want to Log Out.")
        return redirect(url_for('login'))

@app.route('/verify', methods = ['GET', 'POST'])
def verify():
    if current_user.is_authenticated:
        user = User.query.filter_by(id = current_user.id).first()
        if request.method == 'POST':
            user.verified = 'True'
            db.session.commit()
            flash(str(user.verified))
            return redirect(url_for('profile'))

        return render_template('verify.html')
    else:
        flash('We kinda need you to login to verify you. Thanks :D')
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host = 'localhost', port = 5000, debug = True)