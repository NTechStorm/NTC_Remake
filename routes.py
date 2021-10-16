from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime

from NTCoin_Remake import app, db
from NTCoin_Remake.models import User, BlockchainDB, Transactions, load_user

db.create_all()

@app.route('/') 
def index():
    return render_template('index.html')

@app.route('/basictransaction', methods = ['GET', 'POST'])
def basictransaction():
    if current_user.is_authenticated:
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
        recived = Transactions.query.filter_by(reciver = current_user.username).all()
        sent = Transactions.query.filter_by(sender = current_user.username).all()
        return render_template('yourtransactions.html', recived = recived, sent = sent)
    else:
        return redirect(url_for('login'))

@app.route('/buycoins')
def buy():
    if current_user.is_authenticated:
        return render_template('buycoins.html', key=stripe_keys['publishable_key'])
    else:
        flash("Please Login")
        return redirect(url_for('login'))

@app.route('/checkout', methods=['POST'])
def checkout():

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
                user = User(username, email, name, key, generate_password_hash(password), 0)
                db.session.add(user)
                db.session.commit()
                login_user(load_user(user.id))
                flash('Signed Up Sucsessfuly')
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
