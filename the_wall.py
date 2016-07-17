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
    print session
    key_exists=session.get('user_id')
    if key_exists:
        return redirect ('/view_wall')
    else:
        return render_template('index.html')


######################## SHOW WALL #############################################

@app.route('/view_wall')
def view_wall():
    print session
    if 'user_id' not in session:
        flash ('NONE SHALL PASS!', 'login')
        return redirect('/')
    else:
        print 'showing wall'
        print session
        query_posts = mysql.query_db('SELECT * FROM posts LEFT JOIN users ON users_user_id=user_id ORDER BY posts.created_at DESC;')
        query_comments = mysql.query_db('SELECT * from comments LEFT JOIN users ON users_user_id=user_id ORDER BY comments.created_at DESC')
        print 'posts', query_posts,'\n'
        print 'comments', query_comments, '\n'
        #### object returned is query_posts #########
        return render_template('/the_wall.html', query_posts=query_posts, query_comments=query_comments)

######################## REGISTER #############################################
@app.route('/register', methods=['POST'])
def register():
    print 'info received - ', request.form

    first_name=request.form['first_name']
    last_name=request.form['last_name']
    email=request.form['email']
    password=request.form['password']
    password_verify=request.form['password_verify']
    ###################### SESSION FOR TESTING #################################
    session['first_name'] = request.form['first_name']
    session['last_name'] = request.form['last_name']
    session['email'] = request.form['email']
    session['password'] = request.form['password']
    session['password_verify'] = request.form['password_verify']
    ###################### CHECK FIELDS #################################

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

    ###################### IF ALL FIELD ARE VALID #################################
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
            query_insert_new_user = 'INSERT INTO users (first_name, last_name, email, pw_hash, created_at, updated_at) Values (:first_name, :last_name, :email, :pw_hash, NOW(), NOW())'
            mysql.query_db(query_insert_new_user, data_registered)

            ########## CREATE SESSION FOR WALL#############
            query_new_user = 'SELECT * from users WHERE email = :email'
            data_new_email = {'email': email}
            query_for_session_data = mysql.query_db(query_new_user, data_new_email)
            session['user_id']=query_for_session_data[0]['user_id']
            session['first_name']=query_for_session_data[0]['first_name']
            session['last_name']=query_for_session_data[0]['last_name']
            print session
            flash('Registration Success!', 'register')
            return redirect ('/view_wall')
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
        query_login_data = 'SELECT user_id, first_name, last_name, email, pw_hash FROM users WHERE email = :login_email'
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
            session['user_id']=login_verification[0]['user_id']
            session['first_name']=login_verification[0]['last_name']
            session['last_name']=login_verification[0]['last_name']
            print session
            flash('Login Success!', 'login')
            print 'Login success'
            return redirect ('/view_wall')
        else:
            return redirect ('/')

    else:
        return redirect ('/')
######################## LOGIN #############################################
@app.route('/reset_password', methods=['POST'])
def reset_password_submit():
    return redirect('/')
######################## POST #############################################
@app.route('/new_post', methods=['POST'])
def new_post():
    session.get('new_post_text', request.form['new_post'])
    print 'trying to post'
    print session

    query_input_new_post = 'INSERT INTO posts (post_text, users_user_id, created_at, updated_at) VALUES (:new_post_text, :user_id, NOW(), NOW())'
    data_new_post = {
                    'new_post_text': request.form['new_post'],
                    'user_id': session['user_id']
                    }
    mysql.query_db(query_input_new_post, data_new_post)
    print 'New post added to db'
    return redirect('/view_wall')

######################## COMMENT #############################################
@app.route('/new_comment/<post_id>', methods=['POST'])
def new_comment(post_id):
    session.get('new_comment_text', request.form['new_comment'])
    print 'trying to comment'
    print session

    query_input_new_comment = 'INSERT INTO comments (comment_text, users_user_id, created_at, updated_at, posts_post_id) VALUES (:new_comment_text, :user_id, NOW(), NOW(), :post_id)'
    data_new_comment = {
                    'new_comment_text': request.form['new_comment'],
                    'user_id': session['user_id'],
                    'post_id': post_id
                    }
    print "starting query to input comment"
    mysql.query_db(query_input_new_comment, data_new_comment)
    print 'New comment added to db'
    return redirect('/view_wall')


######################## LOGOUT #############################################

@app.route('/clear_session')
def clear_session():
    session.clear()
    return redirect('/')

app.run(debug=True)
