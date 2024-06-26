from flask import Flask, render_template, request, redirect, url_for, session, make_response
from flask_mysqldb import MySQL
import MySQLdb.cursors
import random
import string
import validation
import os
from user import Client, Admin
from datetime import timedelta
import bcrypt
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)


hehe = "".join(random.choices(string.ascii_lowercase+string.ascii_uppercase+string.digits, k=1000))
print(hehe)
app.secret_key = hehe


# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
# Password below must be changed to match root password specified at server installation
# Lab computers use the root password `mysql`
app.config['MYSQL_PASSWORD'] = 'Jameskayle23!'  # Password is in group chat, I don't know if people can hack or not
app.config['MYSQL_DB'] = 'pythonlogin'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6Lej79MpAAAAAAt2WOTiKwRldOYahQ8E7FrjaKt3'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6Lej79MpAAAAAOQ-poskqpjcU2t6ySN8MWhPKSP7'
# Session Timeout
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=10)
app.config['MYSQL_PORT'] = 3306  # DO NOTE THAT THE MYSQL SERVER INSTANCE IN THE LAB IS RUNNING ON PORT 3360.
# Initialize MySQL
mysql = MySQL(app)
user = None


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = request.environ["REMOTE_ADDR"]
    #msg = ''
    print(request.form)
    form = validation.LoginForm(request.form)

    if request.method == "POST" and form.validate():
        username = form.username.data
        password = form.password.data
        # Password Hashing + Salting
        # salting
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM client WHERE name = %s", (username,))
        account = cursor.fetchone()
        salt = (account["password"][0:29]).encode("utf-8")


        # Hashing
        bytes = password.encode("utf-8")
        password = bcrypt.hashpw(bytes, salt)
        password = str(password)
        if account:
            session["loggedin"] = True
            # Start clock for session timeout
            session.permanent = True
            session['id'] = account['id']
            session["username"] = account['name']
            global user
            user = Client(account['id'], account["name"],
                          account['email'], account['card'],
                          account['membership'], account["points"])
            return redirect(url_for("home"))

        else:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("SELECT * FROM admin WHERE name = %s AND password = %s", (username, password,))
            account = cursor.fetchone()
            if account:
                session["loggedin"] = True
                # Start clock for session timeout
                session.permanent = True
                session['id'] = account['id']
                session["username"] = account['name']
                user = Admin(account["id"], account["name"],
                             account["department"], account["position"],
                             account["salary"], account["manager"],
                             account["contact"], account["rating"])

                return redirect(url_for("admin"))
            else:
                msg = "INCORRECT USERNAME/PASSWORD"
    if request.method == "POST":
        msg = "Login Failed"
    response = make_response(render_template('index.html', msg=msg, form=form))
    return response



@app.route('/Register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    print(request.form)
    form = validation.RegistrationForm(request.form)

    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == "POST" and form.validate():
        # Create variables for easy access
        username = form.username.data
        password = form.password.data
        # Password Hashing + Salting
        # salting
        salt = bcrypt.gensalt()
        # Hashing
        email = form.email.data
        # Check for repeating names in Client table
        bytes = password.encode("utf-8")
        password = bcrypt.hashpw(bytes, salt)
        # Check for repeating names in Admin
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM Admin WHERE name = %s", (username,))
        account = cursor.fetchone()
        if account:
            msg = "Username is Taken"
            response = make_response(render_template('register.html', msg=msg, form=form))
            return response

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO client VALUES (NULL, %s, %s, %s, %s, %s, %s)',
                       (username, password, email, "0", False, 0))
        mysql.connection.commit()

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM Client WHERE name = %s", (username,))
        account = cursor.fetchone()

        if account:
            session["loggedin"] = True
            # Start clock for session timeout
            session.permanent = True
            session['id'] = account['id']
            session["username"] = account['name']
            global user
            user = Client(account['id'], account['name'],
                          account["email"], account['card'],
                          account["membership"], account["points"])

            return redirect(url_for("home"))
        else:
            msg = "ERROR OCCURED, CONTACT DEVELOPER"
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Errorsssss'
        # Show registration form with message (if any)
    response = make_response(render_template('register.html', msg=msg, form=form))
    return response


# noinspection PyUnresolvedReferences
@app.route('/Logout')
def logout():
    # Remove session data, log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    user.__del__()
    session.close()
    # Redirect to login page
    return redirect(url_for('login'))


@app.route("/home")
def home():
    if "loggedin" in session:
        response = make_response(render_template('home.html', username=session["username"]))
        return response
    return redirect(url_for("login"))


@app.route('/MyWebApp/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # We need all the account info for the user, so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM Client WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        response = make_response(render_template('profile.html', account=account))
        return response
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


if __name__ == '__main__':
    os.system("cls")

    app.run(debug=True)
