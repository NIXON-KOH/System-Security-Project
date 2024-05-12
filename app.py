import threading
from flask import Flask, render_template, request, redirect, url_for, session, make_response, Response
from flask_mysqldb import MySQL
import MySQLdb.cursors
import random
import string
import validation
import os
from datetime import timedelta, datetime
import bcrypt
import cv2
from flask_wtf.csrf import CSRFProtect
import numpy as np

app = Flask(__name__)


hehe = "".join(random.choices(string.ascii_lowercase+string.ascii_uppercase+string.digits, k=1000))
print(hehe)
app.secret_key = hehe

csrf = CSRFProtect(app)
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
net = cv2.dnn.readNetFromCaffe('proto.txt', 'res10_300x300_ssd_iter_140000.caffemodel')
camera = cv2.VideoCapture(0)

global capture, grey, switch, face
grey = face = 1
switch = capture = 0


# Initialize MySQL
mysql = MySQL(app)



class User:
    def __init__(self, idno, name: str, department: str, position: str,
                 salary: float, manager: bool, contact: int):
        self._id = idno
        self._name = name
        self._department = department
        self._pos = position
        self._salary = salary
        self._manager = manager
        self._contact = contact
    def get_name(self):
        return self._name
    def get_manager(self):
        return self._manager
    def __del__(self):
        del self



@app.route("/")
def index():
    return redirect(url_for("register_face"))

#FACE RECOGNITION

def capture_image():
    # Initialize the camera
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    cap.release()
    return frame


def detect_face(frame):
    global net
    (h, w) = frame.shape[:2]
    blob = cv2.dnn.blobFromImage(cv2.resize(frame, (300, 300)), 1.0,
                                 (300, 300), (104.0, 177.0, 123.0))
    net.setInput(blob)
    detections = net.forward()
    confidence = detections[0, 0, 0, 2]

    if confidence < 0.7:
        return frame

    box = detections[0, 0, 0, 3:7] * np.array([w, h, w, h])
    (startX, startY, endX, endY) = box.astype("int")
    try:
        frame = frame[(startY-10):(endY+10), (startX-10):(endX+10)]
        (h, w) = frame.shape[:2]
        r = 480 / float(h)
        dim = (int(w * r), 480)
        frame = cv2.resize(frame, dim)
    except Exception as e:
        pass
    return frame

def cap(i):
    global capture
    capture = 1 if i < 10 else 0
    print("Image Captured")
    return
def gen_frames():  # generate frame by frame from camera
    global out, capture, rec_frame
    i = 0
    while True:
        success, frame = camera.read()
        if success:
            frame = detect_face(frame)
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            if (capture):
                capture = 0
                p = os.path.sep.join(['shots', "{}_{:0>3}.png".format("Nixon",str(i))])
                cv2.imwrite(p, frame)
                print("Image taken")
                threading.Timer(2, cap, [i]).start()
                i += 1


            try:
                ret, buffer = cv2.imencode('.jpg', cv2.flip(frame, 1))
                frame = buffer.tobytes()

                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n') # yield is a return but for a generator
            except Exception as e:
                pass

        else:
            pass


@app.route('/register_face')
def register_face():
    return render_template('register_face.html')


@app.route('/video_feed')
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/requests-face', methods=['POST', 'GET'])
def tasks():
    global switch, camera, capture
    if request.method == 'POST':
        capture = 1


    elif request.method == 'GET':
        return render_template('register_face.html')

    return render_template('register_face.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = request.environ["REMOTE_ADDR"]
    #msg = ''
    form = validation.LoginForm(request.form)

    if request.method == "POST" and form.validate():
        username = form.username.data
        password = form.password.data
        # Password Hashing + Salting
        # salting
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM user WHERE name = %s", (username,))
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
            user = User(account['id'], account["name"], account["department"], account["position"],
                        account["salary"], account["manager"], account["contact"])
            return redirect(url_for("home"))

        else:
            msg = "INCORRECT USERNAME/PASSWORD"
    if request.method == "POST":
        msg = "Login Failed"
    response = make_response(render_template('index.html', msg=msg, form=form))
    return response

#Check if logged in, role
def check():
    if "loggedin" not in session:
        if User.get_manager():
            return

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
        cursor.execute("SELECT * FROM user WHERE name = %s", (username,))
        account = cursor.fetchone()
        if account:
            msg = "Username is Taken"
            response = make_response(render_template('register.html', msg=msg, form=form))
            return response

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO user VALUES (NULL, %s, %s, %s, %s, %s, %s)',
                       (username, password, email, "0", False, 0))
        mysql.connection.commit()

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM user WHERE name = %s", (username,))
        account = cursor.fetchone()

        if account:
            session["loggedin"] = True
            # Start clock for session timeout
            session.permanent = True
            session['id'] = account['id']
            session["username"] = account['name']
            global user
            user = User(account['id'], account["name"], account["department"], account["position"],
                        account["salary"], account["manager"], account["contact"])

            return redirect(url_for("face_register"))
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
        cursor.execute('SELECT * FROM user WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        response = make_response(render_template('profile.html', account=account))
        return response
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


if __name__ == '__main__':
    os.system("cls")

    app.run(debug=True)
