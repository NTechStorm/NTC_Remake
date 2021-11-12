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

from NTC import app, db, blockchain, bcrypt, blockchainObj, qr
from NTC.models import User, BlockchainDB, Transactions, load_user

db.create_all()

@app.errorhandler(401)
def unauthorized(e):
    flash('Please Log In')
    return redirect(url_for('login'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.authentication == 'bot':
            flash("You have a bot account. You don't need this")
            return redirect('customtransaction/hi')
    else:
        return render_template('index.html')

@app.route('/basictransaction', methods = ['GET', 'POST'])
@login_required
def basictransaction():
    if current_user.authentication == 'bot':
        flash("You have a bot account. You don't need this")
        return redirect('customtransaction/hi')
    else:
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
                            blockchainObj.addTransaction(current_user.username, reciver, amt)
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

@app.route('/customtransaction/<buyer>', methods = ['GET', 'POST'])
@login_required
def customtransaction(buyer):
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
                        blockchainObj.addTransaction(recieverdb.username, current_user.username, amt)
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

@app.route('/profile')
@login_required
def profile():
    if current_user.verified == 'False':
        flash('Get verified to use the site.')
        return redirect(url_for('verify'))
    elif current_user.authentication == 'bot':
        flash("You have a bot account. You don't need this")
        return redirect('customtransaction/hi')
    else: 
        customtranslink = qrcode.make('http://192.168.0.102:8000/customtransaction/' + current_user.username)
        customtranslink.save('static/qr/'+str(current_user.id)+'.jpg')
        return redirect(url_for('profile'))

@app.route('/editprofile')
@login_required
def editprofile():
    user = current_user
    if request.method == 'POST':
        return render_template('editprofile.html', user = user)
    return render_template('editprofile.html', user = user)

@app.route('/yourtransactions')
@login_required
def yourtransactions():
    if current_user.authentication == 'bot':
        flash("You have a bot account. You don't need this")
        return redirect('customtransaction/hi')
    else:
        if current_user.verified == 'False':
            flash('Get verified to use the site.')
            return redirect(url_for('verify'))
        else:
            recived = Transactions.query.filter_by(reciver = current_user.username).all()
            sent = Transactions.query.filter_by(sender = current_user.username).all()
            return render_template('yourtransactions.html', recived = recived, sent = sent)

@app.route('/buycoins')
@login_required
def buy():
    if current_user.authentication == 'bot':
        flash("You have a bot account. You don't need this")
        return redirect('customtransaction/hi')
    else:
        if current_user.verified == 'False':
            flash('Get verified to use the site.')
            return redirect(url_for('verify'))
        else:
            return render_template('buycoins.html', key=stripe_keys['publishable_key'])

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
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
        blockchainObj.addTransaction(blockchainObj(), 'Admin', current_user.username, coinamount)
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
        hashed_password = generate_password_hash(password)
        if emailtest == None:
            try:
                keyGen = blockchainObj.generateKeys()
                user = User(name=name, username=username, email=email, password=hashed_password, key = keyGen, authentication = 'user', verified = 'False')
                db.session.add(user)
                db.session.commit()
                login_user(load_user(user.id))
                qr.add_data('http://127.0.0.1:8000/customtransaction/'+ current_user.username)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                img.save('hi.png')
                flash('You have signed up. Please check your email to verify.')
                return redirect(url_for('profile'))
            except:
                flash('An error occurred while trying to save your user to the database. Try again.')
        else:
            flash('Email already in database. Please try diffrent email, or log in.')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    if current_user.authentication == 'bot':
        flash('Your A bot Account')
        return redirect('customtransaction/hi')
    else:
        logout_user()
        flash('Logged Out Sucsessfuly')
        return redirect(url_for('index'))

@app.route('/verify', methods = ['GET', 'POST'])
@login_required
def verify():
    user = User.query.filter_by(id = current_user.id).first()
    if request.method == 'POST':
        user.verified = 'True'
        db.session.commit()
        flash(str(user.verified))
        return redirect(url_for('profile'))

    return render_template('verify.html')

@app.route('/botsignup', methods = ['GET', 'POST'])
@login_required
def botsignup():
    if current_user.authentication == 'bot':
        return redirect(url_for('index'))
        flash('Youve already signed up for a bot')
    else:
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            if check_password_hash(current_user.password, password):
                curuser = User.query.filter_by(id = current_user.id).first()
                curuser.authentication = 'bot'
                db.session.commit()
                flash("You have a bot account now YAY!")
                return redirect('customtransaction/hi')
            else:
                flash('Incorrect Password')
                return redirect(url_for('profile'))
            return render_template('botsignup.html')
    return redirect(url_for('login'))
