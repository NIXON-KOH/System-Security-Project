import string
import re
from wtforms import Form, StringField, validators, PasswordField, SubmitField
from flask_wtf import FlaskForm

class LoginForm(Form):
    username = StringField("username",[validators.Length(min=2,max=25)],render_kw={"placeholder":"Username"})
    password = PasswordField("password", [validators.length(min=2)],render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")



class RegistrationForm(Form):
    username = StringField("username",[validators.input_required(message='username failed')])
    email = StringField("email",[validators.input_required(message='password failed')])
    password = PasswordField('password', [
        validators.input_required(),
        validators.EqualTo('confirm', message='Passwords must match'),
    ])
    confirm = PasswordField('ConfirmPassword')
    submit = SubmitField("Register")

    def validate_password(self, field):
        if not ((i in field.data) for i in string.ascii_lowercase):
            raise validators.ValidationError("Password does not include lowercase")
        elif not ((i in field.data) for i in string.ascii_uppercase):
            raise validators.ValidationError("Password does not include uppercase")
        elif not ((i in field.data) for i in string.digits):
            raise validators.ValidationError("Password does not include int")
        elif not (8 < len(field.data) < 50):
            raise validators.ValidationError("Password does not meet length")


    def validate_email(self, field):
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        if not re.match(regex, field.data):
            print("Email failed")
            raise validators.ValidationError("Email is invalid")

    def render(self):
        print("hello")
        for field, error in self.errors.items():
            print(error)

