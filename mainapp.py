from flask import Flask, redirect, url_for, session, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import WebApplicationClient
import requests
from oauthlib.oauth2 import InsecureTransportError
import oauthlib.oauth2
import os

def disable_https_requirement():
    oauthlib.oauth2.rfc6749.parameters.ALLOWED_REDIRECT_URI_SCHEMES.append('http')


app = Flask(__name__)

# Flask-Login setup
app.secret_key = 'your_secret_key'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# OAuth configuration
client_id = '242198737454-m3e0js66mr00dhqp8m225gl8ejjra4l2.apps.googleusercontent.com'
client_secret = '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'
authorization_base_url = 'https://accounts.google.com/o/oauth2/auth'
token_url = 'https://accounts.google.com/o/oauth2/token'
redirect_uri = 'http://localhost:5000/callback'
scope = ['profile', 'https://www.googleapis.com/auth/userinfo.email']

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

class User(UserMixin):
    pass


@login_manager.user_loader
def load_user(user_id):
    user = User()
    user.id = user_id
    return user


@app.route('/')
def index():
    if 'google_token' in session:
        google = OAuth2Session(client_id, token=session['google_token'])
        response = google.get('https://www.googleapis.com/oauth2/v1/userinfo')
        if response.status_code == 200:
            user_info = response.json()
            print(user_info)  # Debugging: Print the user info to check the response
            if 'email' in user_info:
                return f'Logged in as {user_info["email"]}<br><a href="/logout">Logout</a>'
            else:
                return f'Could not retrieve email.<br>{user_info}<br><a href="/logout">Logout</a>'
        else:
            return f'Error fetching user info: {response.content}<br><a href="/logout">Logout</a>'
    return 'You are not logged in<br><a href="/login">Login</a>'





@app.route('/login')
def login():
    google = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = google.authorization_url(authorization_base_url, access_type="offline", prompt="consent")
    session['oauth_state'] = state
    return redirect(authorization_url)

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
    except Exception as e:
        return f'Error fetching token: {e}'

    return redirect(url_for('.index'))


@app.route('/logout')
@login_required
def logout():
    session.pop('google_token', None)
    return redirect(url_for('.index'))


if __name__ == '__main__':
    app.run(debug=True)