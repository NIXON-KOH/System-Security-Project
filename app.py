from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors

import validation


app = Flask(__name__)

app.secret_key = 'rqph37>evj-Twac.g}ZX(S]:;)E*[nd2,{yf!4/Q`z6C~Ps$bR' # Change this to your secret key (can be anything, it's for extra protection)
# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
# Password below must be changed to match root password specified at server installation
# Lab computers use the root password `mysql`
app.config['MYSQL_PASSWORD'] = ''#Password is in group chat,, idk if people can hack or not
app.config['MYSQL_DB'] = 'pythonlogin'

app.config['MYSQL_PORT'] = 3306 #DO NOTE THAT THE MYSQL SERVER INSTANCE IN THE LAB IS RUNNING ON PORT 3360.
# Intialize MySQL
mysql = MySQL(app)

@app.route('/MyWebApp/', methods=['GET', 'POST'])
def login():
    msg = ''
    form = validation.LoginForm(request.form)

    if request.method == "POST" and form.validate():
        username = form.username.data
        password = form.password.data

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE username = %s AND password = %s",(username,password,))
        account = cursor.fetchone()
        if account:
            session["loggedin"] = True
            session['id'] = account['id']
            session["username"] = account['username']
            return redirect(url_for("home"))
        else:
            msg = "INCORRECT USERNAME/PASSWORD"
    return render_template('index.html', msg=msg, form=form)
@app.route('/MyWebApp/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    form = validation.RegistrationForm(request.form)
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and form.validate():
        # Create variables for easy access
        
        username = form.username.data
        password = form.password.data
        email = form.email.data
        print(username, password, email)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE username = %s",(username,))
        account = cursor.fetchone()
        if account:
            msg="Username is Taken"
            return render_template('register.html', msg=msg, form=form)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, password, email,))
        mysql.connection.commit()
        msg = 'You have successfully registered!'
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
        # Show registration form with message (if any)
    return render_template('register.html', msg=msg, form=form)

@app.route('/MyWebApp/logout')
def logout():
    # Remove session data, log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login'))

@app.route("/MyWebApp/home")
def home():
    if "loggedin" in session:
        return render_template('home.html', username=session["username"])
    return redirect(url_for("login"))

@app.route('/MyWebApp/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

if __name__== '__main__':
    app.run(debug=True)