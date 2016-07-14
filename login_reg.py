from flask import Flask, render_template, redirect, request, flash, session
from datetime import datetime
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import os
import re


app=Flask(__name__)
bcrypt=Bcrypt(app) ##Encryption
mysql=MySQLConnector(app, 'the_wall')
app.secret_key=os.urandom(24) ##session

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
PASSWORD_REGEX=re.compile(r'^([0-9]+[a-zA-Z]+|[a-zA-Z]+[0-9]+)[0-9a-zA-Z]*$')

@app.route('/')
def index():
    return render_template('login_reg.html')

@app.route('/register', methods=['POST'])
def register():
    print 'info received - ', request.form

    first_name=request.form['first_name']
    last_name=request.form['last_name']
    email=request.form['email']
    password=request.form['password']
    password_verify=request.form['password_verify']

    session['first_name'] = request.form['first_name']
    session['last_name'] = request.form['last_name']
    session['email'] = request.form['email']
    session['password'] = request.form['password']
    session['password_verify'] = request.form['password_verify']
    print first_name, last_name, email, password, password_verify

    required_fields=True
    valid = True #check for redirecting
    for key,value in request.form.items():
        if not value:
            required_fields=False

    if required_fields==False:
        flash('All fields are required', 'register')
        valid=False

    if not first_name.isalpha():
        flash('First Name - use only alphabet letters', 'register')
        valid=False

    if not last_name.isalpha():
        flash('Last Name - use only alphabet letters', 'register')
        valid=False
    # try:
    #     datetime.strptime(birthday, '%m/%d/%Y')
    #     if datetime.strptime(birthday, '%m/%d/%Y') > datetime.today():
    #         flash("Can't put date in future")
    #
    # except ValueError:
    #     flash('Wrong date format', 'birthday')


    if not EMAIL_REGEX.match(email):
        flash('invalid email address', 'register')
        valid=False
    # if len(password)<8 or not PASSWORD_REGEX.match(password):
    #     flash('Password must be more than 8 characters, contain 1 uppercase letter and a mixture of numbers and letters')

    if len(password)<8 or password.islower() or password.isdigit() or password.isalpha():
        flash('Password must be more than 8 characters, contain 1 uppercase letter and a mixture of numbers and letters', 'register')
        valid=False

    if password != password_verify:
        flash("passwords don't match", 'register')
        valid=False

    if valid==True:
        pw_hash = bcrypt.generate_password_hash(password)
        data_registered = {
                        'first_name':  first_name,
                        'last_name': last_name,
                        'email': email,
                        'pw_hash': pw_hash
                        }
        query_check_email_exists = 'SELECT email from users where email = :email'
        query_email_compare = mysql.query_db(query_check_email_exists, data_registered)

        if not query_email_compare:
            query_insert_new_user = 'INSERT INTO users (first_name, last_name, email, pw_hash) Values (:first_name, :last_name, :email, :pw_hash)'
            mysql.query_db(query_insert_new_user, data_registered)
            flash('Registration Success!', 'register')
        else:
            flash('Email Exists!', 'register')
            print 'email exists'
            valid=False
        return redirect('/')
    else:
        return redirect('/')



######################## LOGIN #############################################
@app.route('/login', methods=['POST'])
def login():
    login_email=request.form['login_email']
    login_password=request.form['login_password']

    session['login_email'] = request.form['login_email']
    session['login_password'] = request.form['login_password']
    valid=True

    required_fields=True
    for key,value in request.form.items():
        if not value:
            required_fields=False
            valid=False

    if required_fields==False:
        flash('All fields are required', 'login')
        print 'empty fields'

    if not EMAIL_REGEX.match(login_email):
        flash('invalid email address', 'login')
        valid=False

    if valid==True:
        print 'session is', session
        query_login_data = 'SELECT email, pw_hash FROM users WHERE email = :login_email'
        login_data = {
                    'login_email': request.form['login_email']
                    }
        login_verification = mysql.query_db(query_login_data, login_data)
        print login_verification

        if len(login_verification)==0:
            flash('No account with this email was found', 'login')
            print 'email not found'
            valid=False

        elif not bcrypt.check_password_hash(login_verification[0]['pw_hash'], login_password):
            flash('incorrect password', 'login')
            print 'incorrect password'
            valid=False

        if valid == True:
            flash('Login Success!', 'login')
            print 'success'
            return redirect ('/')
        else:
            return redirect ('/')

    else:
        return redirect ('/')

@app.route('/clear_session')
def clear_session():
    session.clear()
    return redirect('/')

app.run(debug=True)
