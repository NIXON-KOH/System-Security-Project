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
from oauthlib.oauth2 import InsecureTransportError
import oauthlib.oauth2
from flask_login import LoginManager, UserMixin
from requests_oauthlib import OAuth2Session
from src.anti_spoof_predict import AntiSpoofPredict
from src.generate_patches import CropImages
from src.utility import parse_model_name
from deepface import DeepFace
import json
def disable_https_requirement():
    oauthlib.oauth2.rfc6749.parameters.ALLOWED_REDIRECT_URI_SCHEMES.append('http')

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

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

client_id = '242198737454-m3e0js66mr00dhqp8m225gl8ejjra4l2.apps.googleusercontent.com'
client_secret = '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'
authorization_base_url = 'https://accounts.google.com/o/oauth2/auth'
token_url = 'https://accounts.google.com/o/oauth2/token'
redirect_uri = 'http://localhost:5000/callback'
scope = ['profile', 'https://www.googleapis.com/auth/userinfo.email']
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

class Useri(UserMixin):
    pass


@login_manager.user_loader
def load_user(user_id):
    user = Useri()
    user.id = user_id
    return user

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
    return redirect(url_for("login_face"))

#FACE RECOGNITION
net = cv2.dnn.readNetFromCaffe('proto.txt', 'res10_300x300_ssd_iter_140000.caffemodel')
camera = cv2.VideoCapture(0)

global capture, grey, switch, face, login
grey = face = 1
switch = login = False

# Initialize MySQL
mysql = MySQL(app)

def log(msg):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('INSERT INTO log VALUES (NULL, %s, %s, %s)',
                   (datetime.now(), user.get_id(), msg,))
    mysql.connection.commit()

def capture_image():
    # Initialize the camera
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    cap.release()
    return frame


def detect_face(frame):
    global net, login
    (h, w) = frame.shape[:2]

    blob = cv2.dnn.blobFromImage(cv2.resize(frame, (300, 300)), 1.0,
                                 (300, 300), (104.0, 177.0, 123.0))
    net.setInput(blob)
    detections = net.forward()
    detections = net.forward()
    confidence = detections[0, 0, 0, 2]

    if confidence < 0.7:
        login = False
        return frame

    model_test = AntiSpoofPredict(0)
    image_cropper = CropImages()
    image = frame
    image_bbox = model_test.get_bbox(image)
    prediction = np.zeros((1,3))
    for model_name in os.listdir("./src/anti_spoof_models"):
        h_input, w_input, model_type, scale = parse_model_name(model_name)
        param = {
            "org_img": image,
            "bbox": image_bbox,
            "scale": scale,
            "out_w": w_input,
            "out_h": h_input,
            "crop": True,
        }
        if scale is None:
            param["crop"] = False
        img = image_cropper.crop(**param)
        prediction += model_test.predict(img, os.path.join("./src/anti_spoof_models", model_name))

    # draw result of prediction
    label = np.argmax(prediction)
    value = prediction[0][label]/2
    if not (label == 1 and value > 0.95):
        print(f"Fake : {value}")
        login = False
        return frame
    box = detections[0, 0, 0, 3:7] * np.array([w, h, w, h])
    (startX, startY, endX, endY) = box.astype("int")
    try:
        frame = frame[(startY-10):(endY+10), (startX-10):(endX+10)]
        (h, w) = frame.shape[:2]
        r = 480 / float(h)
        dim = (int(w * r), 480)
        frame = cv2.resize(frame, dim)

        if (login):
            login = False
            cv2.imwrite('image.jpg', frame)
            for file in os.listdir("stored"):
                print(file)
                if file.endswith(".jpg"):
                    print(file)
                    result = DeepFace.verify(img1_path="image.jpg",
                                             img2_path=f"./stored/{file}",
                                             model_name="VGG-Face")
                    print("hello")
                    print(result)
                    if result["verified"]:
                        os.remove("image.jpg")
                        return redirect("home")
                        break
            os.remove("image.jpg")
            print("Not Found")
    except Exception as e:
        pass

    return frame

def gen_frames():  # generate frame by frame from camera
    global out, rec_frame, login
    i = 0
    while True:
        success, frame = camera.read()
        if success:
            frame = detect_face(frame)

        try:
            ret, buffer = cv2.imencode('.jpg', cv2.flip(frame, 1))
            frame = buffer.tobytes()

            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n') # yield is a return but for a generator
        except Exception as e:
            pass

        else:
            pass
@app.route('/video_feed')
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

#Login Face
@app.route('/login_face')
def login_face():
    return render_template('login_face.html')


@app.route("/requests-face-login", methods=["POST","GET"])
def task_login():
    global switch, camera, login
    if request.method == 'POST':
        login = True
    elif request.method == 'GET':
        return render_template('login_face.html')
    return render_template('login_face.html')

@app.route("/googlelogin")
def googlelogin():
    google = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = google.authorization_url(authorization_base_url, access_type="offline", prompt="consent")
    session['oauth_state'] = state
    return redirect(authorization_url)

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
            return redirect(home)

        else:
            msg = "INCORRECT USERNAME/PASSWORD"
    if request.method == "POST":
        msg = "Login Failed"
    return render_template('index.html', msg=msg, form=form)


def fetch_token_without_https(url, client_id, client_secret, authorization_response, state):
    # Define a custom OAuth2Session subclass
    class InsecureOAuth2Session(OAuth2Session):
        def fetch_token(self, *args, **kwargs):
            try:
                # Try to fetch token using the parent class
                return super().fetch_token(*args, **kwargs)
            except InsecureTransportError:
                # If InsecureTransportError is raised, ignore it
                pass

    # Create an instance of the custom OAuth2Session subclass
    google = InsecureOAuth2Session(client_id, state=state, redirect_uri=redirect_uri)

    # Fetch token without HTTPS verification
    token = google.fetch_token(url, client_secret=client_secret, authorization_response=authorization_response)
    return token

@app.route('/callback')
def callback():
    oauth_state = request.args.get('state', '')
    google = OAuth2Session(client_id, state=oauth_state, redirect_uri=redirect_uri)

    try:
        token = google.fetch_token(token_url, client_secret=client_secret, authorization_response=request.url)
        session['google_token'] = token
        return redirect(url_for('google_check'))
    except Exception as e:
        return f'Error fetching token: {e}'

@app.route("/google_check")
def google_check():
    if 'google_token' in session:
        google = OAuth2Session(client_id, token=session['google_token'])
        response = google.get('https://www.googleapis.com/oauth2/v1/userinfo')

        if response.status_code == 200:
            user_info = response.json()
            print(user_info)  # Debugging: Print the user info to check the response
            if 'email' in user_info:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute("SELECT * FROM user WHERE google_id = %s",(user_info["id"],))
                account = cursor.fetchone()
                if not account: #Login
                    cursor.execute("INSERT INTO user VALUES (NULL, %s, NULL, %s. %s, %s, %s, %s, %s)",
                                   user_info['name'], "default", "staff", 0, False, 0)
                    mysql.connection.commit()
                    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    cursor.execute("SELECT * FROM user WHERE name = %s", (user_info["id"],))
                    account = cursor.fetchone()
                    register = True

                session["loggedin"] = True
                session.permanent = True
                session["id"] = account["id"]
                session["username"] = account["name"]
                global user
                user = User(account['id'], account["name"], account["department"], account["position"],
                            account["salary"], account["manager"], account["contact"])
                if register:
                    return redirect(url_for("face_register"))
                else:
                    return redirect(url_for("home"))

            else:
                return f'Could not retrieve email.<br>{user_info}<br><a href="/logout">Logout</a>'
        else:
            return f'Error fetching user info: {response.content}<br><a href="/logout">Logout</a>'
#Check if logged in, role
def check():

    if "loggedin" not in session:
        if User.get_manager():
            pass
    return 'You are not logged in<br><a href="/login">Login</a>'

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



@app.route('/Logout')
def logout():
    if user.get_logintype() == False:
        session.pop('google_token', None)
    else:
        session.pop('google_token', None)
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
