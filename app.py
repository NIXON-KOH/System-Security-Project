from flask import Flask, render_template, request, redirect, url_for, session, make_response
from flask_mysqldb import MySQL
import MySQLdb.cursors
import random
import string
import validation
import os
from datetime import timedelta
import bcrypt
import cv2
from flask_wtf.csrf import CSRFProtect


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
    return redirect(url_for("login"))

#FACE RECOGNITION
def capture_image():
    # Initialize the camera
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    cap.release()
    return frame

# Function to detect faces in an image
def detect_faces(image):
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.3, minNeighbors=5)
    return faces

# Function to save face image to file
def save_face_image(image, username):
    face_dir = 'faces'
    if not os.path.exists(face_dir):
        os.makedirs(face_dir)
    filename = os.path.join(face_dir, f'{username}.jpg')
    cv2.imwrite(filename, image)

# Function to load face images
def load_face_images():
    face_dir = 'faces'
    face_images = {}
    for filename in os.listdir(face_dir):
        username = os.path.splitext(filename)[0]
        image = cv2.imread(os.path.join(face_dir, filename))
        face_images[username] = image
    return face_images
user_face = {}

@app.route('/face_register', methods=['GET', 'POST'])
def face_register():
    msg = ""
    if request.method == 'POST':
        username = request.form['username']
        # Capture face image
        face_image = capture_image()
        # Detect faces in the image
        faces = detect_faces(face_image)
        if len(faces) == 1:
            # Save the face image
            save_face_image(face_image, username)
            # Store the username and face image
            user_face[username] = {'face_image': face_image}
            return render_template("home")
        else:
            msg = "Error: Could not detect face or multiple faces detected. Please try again."
            return render_template('register.html',msg=msg)
    return render_template('register.html',msg=msg)

@app.route('/face_login', methods=['GET', 'POST'])
def face_login():
    if request.method == 'POST':
        # Capture face image
        face_image = capture_image()
        # Detect faces in the image
        faces = detect_faces(face_image)

        if len(faces) == 1:
            print("Face Detected")
            # Loop through registered users to find a match
            for username, data in user_face.items():
                registered_face = data['face_image']
                # Compare face images using norm correlation coefficient
                result = cv2.matchTemplate(face_image, registered_face, cv2.TM_CCOEFF_NORMED)
                _, similarity, _, _ = cv2.minMaxLoc(result)
                if similarity >= 0.7:  # Adjust threshold as needed
                    return url_for("home")
            return "Face not recognized. Please try again."
        else:
            return "Error: Could not detect face or multiple faces detected. Please try again."
    return render_template('login.html')

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
