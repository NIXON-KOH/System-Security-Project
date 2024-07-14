#imports 
import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0' # Turn off rounding error warning in custom oneDNN operation in tensorflow
from flask import Flask, render_template, redirect, url_for, session, request, Response, jsonify
import validation
import joblib
import cv2 
import string 
import random
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta, datetime
import json
import bcrypt
from functools import wraps
from requests_oauthlib import OAuth2Session
from classes import User, UserDatabase
from ua_parser import user_agent_parser
import requests
import pandas as pd
import numpy as np
from deepface import DeepFace
from src.utility import parse_model_name
from src.anti_spoof_predict import AntiSpoofPredict
from src.generate_patches import CropImage
import pyotp
from virus_total_apis import PublicApi as VirusTotalPublicApi
import hashlib
from werkzeug.utils import secure_filename

os.system("cls") # Clean the terminal

#Load all the Models (Use sklearn 1.5.0, may be inconsistent with other versions)
model = joblib.load("models/risk_auth_model.pkl") # Risk Based Authentication 
print("Risk Based Authentication model Loaded.")

label_encoder = joblib.load("models/label_encoders.pkl") # Risk Based Authentication
print("Risk based Authentication label Loaded.")

net = cv2.dnn.readNetFromCaffe('models/proto.txt', 'models/res10_300x300_ssd_iter_140000.caffemodel') # Facial Recognition
print("Facial Recognition model loaded.")

with open('secrets.json') as f:
    secrets = json.load(f)
print("Secrets Loaded.")

#App settings 
app = Flask(__name__) # Initialises the app
app.secret_key = "".join(random.choices(string.ascii_lowercase+string.ascii_uppercase+string.digits, k=10)) # k = size of secret key
print("Secret Key : ", app.secret_key)
csrf = CSRFProtect(app) #CSRF token
csrf.init_app(app)
print("CSRF Token Loaded.")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10) #session timeout
print("Session Timeout Loaded : ", app.config['PERMANENT_SESSION_LIFETIME'])

#Database Connection Details
db = UserDatabase(secrets['password']['mysql'])
print("Database Configuration Complete.")

#Recaptcha information
app.config['RECAPTCHA_PUBLIC_KEY'] = secrets["apikeys"]["captcha_public_key"]
app.config['RECAPTCHA_PRIVATE_KEY'] = secrets["apikeys"]["captcha_private_key"]
print("Recaptcha Configuration Complete.")

#Oauth Information
client_id = secrets["apikeys"]["Oauth_client_id"]
client_secret = secrets["apikeys"]["Oauth_client_secret"]
authorization_base_url = 'https://accounts.google.com/o/oauth2/auth'
token_url = 'https://accounts.google.com/o/oauth2/token'
redirect_uri = 'http://localhost:5000/callback'
scope = ['profile', 'https://www.googleapis.com/auth/userinfo.email']
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
print("Oauth Information Loaded.")

app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 #16 MB max
# Initialize VirusTotal API client
vt = VirusTotalPublicApi(secrets['apikeys']["Virus_total_api"])
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', "pdf"}

print("Virus Total Information Loaded")
print("\n")

tokens = {"meow":pyotp.random_base32()}
login_req = 0
idno = 0 

@app.errorhandler(404) # not found Error handler
def not_found(error):
    return "Not Found", 404

@app.errorhandler(405) # not Allowed Error handler
def not_Allowed(error):
    return "Not Allowed", 405

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login",methods=["POST","GET"] )
def login():
    msg = ""
    form = validation.LoginForm(request.form)
    if request.method == "POST" and form.validate():
        salt = bcrypt.gensalt()
        pw = 'admin'.encode('utf-8')
        pw = bcrypt.hashpw(pw,salt)

        username = form.username.data
        password = form.password.data

        print(username, password) #admin admin
        # Password Hashing + Salting
        # salting
        account = db.select_1(f"SELECT * FROM USER WHERE NAME='{username}'")

        if account is not None:
            res = bcrypt.checkpw(password.encode('utf-8'), account[2].encode('utf-8'))
            if res:
                global idno
                idno = account[0]
                return redirect(f"/risk")
        else:
            msg = "INCORRECT USERNAME/PASSWORD"
    if request.method == "POST":
        msg = "Login Failed"
    return render_template('loginpage.html', msg=msg, form=form, active_sessions=get_active_sessions())


#Oauth

@app.route("/googlelogin")
def googlelogin():
    google = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = google.authorization_url(authorization_base_url, access_type="offline", prompt="consent")
    session['oauth_state'] = state
    return redirect(authorization_url)

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
            '''
            {'id': '100121233737772043805', 
            'email': 'mesphistopheles4@gmail.com', 
            'verified_email': True, 
            'name': 'Mephisto pheles', 
            'given_name': 'Mephisto', 
            'family_name': 'pheles', 
            'picture': 'https://lh3.googleusercontent.com/a/ACg8ocIN1w2RbwIOntfgGZXaRDxyUxjldR0SmYMiaScMFPlf8dPY9HA=s96-c'}
            '''
            print(user_info['email'])
            account = db.select_1(f"SELECT * FROM user WHERE email='{user_info['email']}'")
            print(account)
            if account: #Login
                global idno
                idno = account[0]
                return redirect(f"/risk")

            else:
                msg = 'BAD EMAIL.'
                return redirect(url_for("login"))
        else:
            msg = "BAD EMAIL."
            return redirect(url_for("login"))

def predict_risk(data):
    data['Login Timestamp'] = pd.to_datetime(data['Login Timestamp'])
    data['Hour'] = data['Login Timestamp'].dt.hour
    data['Day'] = data['Login Timestamp'].dt.day
    data['Month'] = data['Login Timestamp'].dt.month
    data['Day of Week'] = data['Login Timestamp'].dt.dayofweek

    # Drop the original Login Timestamp column
    data.drop(columns=['Login Timestamp'], inplace=True)

    # Encode categorical variables using the label encoders
    for column, le in label_encoder.items():
        # Handle unseen labels by assigning them to a new category
        data[column] = data[column].apply(lambda x: x if x in le.classes_ else 'unknown')
        # Update the label encoder classes to include 'unknown'
        le.classes_ = np.append(le.classes_, 'unknown')
        data[column] = le.transform(data[column])
    predictions = model.predict_proba(data)
    return predictions


@app.route("/risk")
def rba(idno):
    ua = request.headers.get('User-Agent')
    r = requests.get("https://ipinfo.io/").json()
    # ua_parser is above 0.15 (currently using 0.18) which supports user_agent_parser.Parse() which caches UA
    # improving performance for real world datasets
    parsed = user_agent_parser.Parse(ua) 
    new_login = pd.DataFrame({
        "Login Timestamp": [datetime.now()],
        'User ID': [idno], 
        'Round-Trip Time [ms]': [150],
        'IP Address': r["ip"],
        'Country': [ r["country"]],
        'Region': [r["country"]],
        'City': [r["city"]],
        'ASN': [29],
        'User Agent String': [request.headers.get("User-Agent")],
        'Browser Name and Version': [f"{parsed['user_agent']['family']} {parsed['user_agent']['major']}.{parsed['user_agent']['minor']}.{parsed['user_agent']['patch']}"],
        'OS Name and Version': [f"{parsed['os']['family']} {parsed['os']['major']}.{parsed['os']['minor']}.{parsed['os']['patch']}"],
        'Device Type': ['Desktop'],
        'Login Successful': [False]
    })
    prediction = predict_risk(new_login)[0][0]
    print("Risk Factor : ",prediction)
    db.log(idno, f"Login Risk : {prediction}")
    if prediction < 0.5: #Facial Recognition
        return redirect("/face")
    elif prediction < 0.7: #totp
        return redirect("/totp")
    else:
        return redirect("/authenticated")

    

######################
## Face Recognition ##
######################

#Initialise Camera
def capture():
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    cap.release()
    return frame

#processes the Frames for face
def detect_face(frame):

    #Face Detection
    (h, w) = frame.shape[:2] # Takes Height and width of image
    #Turns the frame from 0 to 255 (color code) into 0~1 maxtrix
    #Frame, resize the frame to 300 x 300, Scale factor of 1, New image size should be 300x300, Mean value image (arbitary)
    blob = cv2.dnn.blobFromImage(cv2.resize(frame,(300, 300)), 1.0, (300, 300), (104.0, 177.0, 123.0)) 
    net.setInput(blob) #Set the blob as input image(matrix form)
    detections = net.forward() #Evaluates blob
    confidence = detections[0, 0, 0, 2]

    if confidence < 0.7: return frame # if no face is found, return frame
    
    
    model_test = AntiSpoofPredict(0)
    image_cropper = CropImage()
    image = frame
    image_bbox = model_test.get_bbox(image)
    prediction = np.zeros((1,3))
    for model_name in os.listdir("./src/resources/anti_spoof_models"):
        h_input, w_input, _, scale = parse_model_name(model_name)
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
        prediction += model_test.predict(img, os.path.join("./src/resources/anti_spoof_models", model_name))
    label = np.argmax(prediction)
    value = prediction[0][label]/2
    if not (label == 1 and value >= 0.9):
        print(f"Fake : {value}")
        return frame

    box = detections[0, 0, 0, 3:7] * np.array([w, h, w, h])
    (startX, startY, endX, endY) = box.astype("int")
    try:
        frame = frame[(startY-10):(endY+10), (startX-10):(endX+10)]
        (h, w) = frame.shape[:2]
        r = 480 / float(h)
        dim = (int(w * r), 480)
        frame = cv2.resize(frame, dim)
        global login_req
        if login_req:
            cv2.imwrite('image.jpg', frame)
            result = DeepFace.verify(img1_path="image.jpg",
                                     img2_path=f"./stored/{idno}.jpg",
                                     model_name="VGG-Face")
            print(result)
            os.remove("image.jpg")
            if result["verified"] and result['threshold'] > 0.4:
                print("found")
                camera.release()
                login_req = -1
                return frame
            login_req = 0
            print("Not Found")


    except:
        pass

    return frame

camera = cv2.VideoCapture(0)

#Recieves the Frames after being processed
def gen_frames():
    while True:
        success, frame = camera.read()
        if success:
            frame = detect_face(frame)
        try:
            ret, buffer = cv2.imencode('.jpg', cv2.flip(frame,1))
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n') # yield is a return but for a generator
        except Exception as e:
            pass

        else:
            pass


#Push Frames to the front end
@app.route("/video_feed")
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route("/face", methods=["POST","GET"]) #My solution to controlling the authentication lol
def face_recog():
    global login_req
    if login_req == -1:
        return redirect(url_for('Authenticated'))
    if request.method == "POST":
        login_req = idno #Requests for a face recognition
    return render_template("login_face.html")

############ 
## TOTP ###
###########

@app.route("/totp", methods=["POST","GET"])
def totp():

    form = validation.Totpform(request.form)

    if request.method == 'POST' and form.validate() and idno:    

        totp_code = form.totp.data

        totp_secret = db.select_1(f"SELECT TOTPSECRET FROM USER WHERE id={idno}")
        totp_secret = str(totp_secret[0])
        
        totp = pyotp.TOTP(totp_secret)

        if totp.verify(totp_code):
            print("Authenticated!!")
            return redirect(f"/authenticated")
        else:
            return login()
        
    return render_template('totp_verify.html', form=form)


@app.route("/authenticated")
def Authenticated():
    global idno
    if "loggedin" in session:
        session["loggedin"] = True
        session['id'] = idno
        account = db.select_1(f"SELECT * FROM user WHERE id={idno}")[0]
        print(account)
        print(session)
        session['info'] = User(account[0],account[1],account[3],account[4],account[5])
        session.permanent = True
        token =  pyotp.random_base32()
        db.log(idno, f"Loggedin : {idno}")
        tokens[session['id']] = token
        return redirect("/profile")
    return redirect("/login")

########################
## Session Management ##
########################

@app.route("/endpoint", methods=["POST","GET"])
def recieve_data():
    print("bro??")
    if request.method == "POST":
        print("Recieve data")
    data = request.json
    print(data)
    if 'activeSessionId' in data:
        print(f"Active Session ID : {data['activeSessionId']}")
    return "Data Recieved"

@app.route('/status')
def status(): 
    username = session['username']
    session_token = session['token']
    
    if not session_token or tokens.get(username) != session_token:
        return jsonify(status="Invalid session")
    print("Session Valid")
    return jsonify(status="Session valid")

@app.route("/get_active_sessions")
def get_active_sessions():
    print(tokens)
    return [(user, token) for user, token in tokens.items()]

@app.route('/invalidate_others', methods=['POST','GET'])
def invalidate_others():
    print("Invalidated")
    if 'username' in session and 'token' in session:
        username = session['username']
        token = session['token']
        tokens[username] = token
        return jsonify(status="Other sessions invalidated")
    return jsonify(status="No active session")

@app.route("/profile")
def profile():
    if "loggedin" in session:
        return render_template('index.html')
    return redirect("/login")

@app.route("/logout")
def logout():
    global idno
    if "loggedin" in session:
        session.pop("id", None)
        session.pop('loggedin', None)
        session.pop('info', None)
        idno = 0
        username = session.pop('username', None)
        if username:
            tokens.pop(username, None)
        session.clear()
    return redirect(url_for('login'))

@app.route('/setup')
def totp_setup():
    if 'loggedin' in session:
        totp_secret = pyotp.random_base32()
        print(totp_secret)
        # TODO: PLEASE CHANGE NAME AND ISSUER NAME TO HTML INPUT
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name="mesphistopheles4@gmail.com", issuer_name="Nixon Koh")
        print(totp_uri)
        return render_template('totp_register.html', totp_uri=totp_uri)
    return redirect(url_for('login'))

#####################
## VIRUS TOTAL API ##
#####################
@app.route("/maliciousupload", methods=["POST"])
def malicious_file_upload():
    file_md5 = "0f06a4736bff917f2390740a71db11d6"
     # Retrieve basic file report from VirusTotal using file_md5
    response = vt.get_file_report(file_md5)

    # Check for malicious detection
    if 'results' in response and response['results'].get('positives', 0) > 0:
        message = "There is something wrong with the file. It may be malicious."
        report_url = url_for('view_report', report=json.dumps(response, sort_keys=False, indent=4))
        return render_template('result.html', message=message, report_url=report_url)

    # If no malicious detection, upload is successful
    message = "File successfully uploaded."
    report_url = url_for('view_report', report=json.dumps(response, sort_keys=False, indent=4))
    return render_template('result.html', message=message, report_url=report_url)

@app.route('/upload', methods=['POST'])
def upload_file():

    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        db.log(idno,f"Report Complete: {file_path}")
        # Calculate MD5 hash of the uploaded file
        md5_hash = hashlib.md5()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):   
                md5_hash.update(chunk)
        file_md5 = md5_hash.hexdigest() #JPG

        # Retrieve basic file report from VirusTotal using file_md5
        response = vt.get_file_report(file_md5)

        # Check for errors in the response
        if 'results' not in response or response['results']['response_code'] == 0:
            # If the file is not found on VirusTotal, upload it
            upload_response = vt.scan_file(file_path)
            if 'results' in upload_response:
                resource = upload_response['results']['resource']
            else:
                message = "Error in upload response"
                return render_template('result.html', message=message, report_url=None)

            # Notify the user to wait for the report
            message = "File is being scanned. Please refresh the page after a while to see the results."
            report_url = url_for('view_report', resource=resource)
            return render_template('result.html', message=message, report_url=report_url)

        # Check for malicious detection
        if 'results' in response and response['results'].get('positives', 0) > 0:
            message = "There is something wrong with the file. It may be malicious."
            report_url = url_for('view_report', report=json.dumps(response, sort_keys=False, indent=4))
            return render_template('result.html', message=message, report_url=report_url)

        # If no malicious detection, upload is successful
        message = "File successfully uploaded."
        report_url = url_for('view_report', report=json.dumps(response, sort_keys=False, indent=4))
        return render_template('result.html', message=message, report_url=report_url)
    else:
        return 'Invalid file type'

@app.route('/report')
def view_report():
    if "loggedin" in session:
        resource = request.args.get('resource')

        if resource:
            response = vt.get_file_report(resource)
            if 'results' in response and response['results']['response_code'] != -2:
                report = json.dumps(response, sort_keys=False, indent=4)
                return render_template('report.html', report=report)
            else:
                message = "If view report not working, wait awhile and refresh"
                return render_template('result.html', message=message, report_url=url_for('view_report', resource=resource))
        else:
            report = request.args.get('report')
            print(report)

            return render_template('report.html', report=report)
    else:return redirect(url_for('login'))


@app.route("/rooms",methods=["POST"])
def rooms():
    if "loggedin" in session:
        rooms = db.select_all("SELECT * FROM ROOM")
        if request.method == "POST":
            roomno = request.roomno.data
            db.insert_query("DELETE FROM ROOM WHERE ROOMNO='%s'",(roomno))
        return render_template("rooms.html", rooms=rooms) #Yall just design cards then for loop it lol
    else:return redirect(url_for('login'))

#EDIT ROOM TO PROPERLY EDIT DB, add in image functions, connect to totalvirus api
@app.route("/editroom/<roomno>",methods=["POST"])
def editroom(roomno):
    if "loggedin" in session:
        form = validation.editroom(request.form)
        if request.method == "POST" and form.validate():
            name = form.name.data
            cost = form.cost.data
            availability = form.availability.data
            max_occupancy = form.max.data
            smoking = form.smoking.data
            db.insert_query(f"UPDATE ROOM VALUES (NULL, %s, %s, %s, %s, %s) WHERE id={roomno}",(name, cost, availability, max_occupancy, smoking))
        
        roominfo = db.select_1(f"SELECT * FROM ROOM WHERE id='{roomno}'")
        return render_template("editroom.html", roominfo=roominfo, form=form)
    else:return redirect(url_for('login'))


@app.route("/addroom",methods=["POST","GET"])
def addroom():
    if "loggedin" in session:
        form = validation.addroom(request.form)
        msg = ""
        if request.method == "POST" and form.validate():
            name = form.name.data
            cost = form.cost.data
            availability = form.availability.data
            max_occupancy = form.max.data
            smoking = form.smoking.data
            db.insert_query("INSERT INTO ROOM VALUES (NULL, %s, %s, %s, %s, %s)",(name, cost, availability, max_occupancy, smoking))
        elif request.method == "POST":
            msg = "Invalid Field"
        return render_template("addroom.html", msg = msg, form=form)
    else:return redirect(url_for('login'))


app.run()
camera.release()
print("App is Down. Goodbye.")