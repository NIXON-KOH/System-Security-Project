
import re
from wtforms import Form, StringField, validators, PasswordField, SubmitField
from flask_wtf import FlaskForm, RecaptchaField


class LoginForm(Form):
    username = StringField("username", [validators.Length(min=2, max=25)], render_kw={"placeholder": "Username"})
    password = PasswordField("password", [validators.length(min=2)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")



class RegistrationForm(Form):
    username = StringField("username")
    email = StringField("email")
    password = PasswordField('password')
    submit = SubmitField("Register")
    recaptcha = RecaptchaField()

    @staticmethod
    def validate_password(self, field):
        if re.search('[0-9]', field.data) is None:
            raise validators.ValidationError("Password does not include int")
        elif re.search('[A-Z]', field.data) is None:
            raise validators.ValidationError("Password does not include uppercase")
        elif re.search('[a-z]', field.data) is None:
            raise validators.ValidationError("Password does not include Lowercase")
        elif not (8 < len(field.data) < 50):
            raise validators.ValidationError("Password does not meet length")

    @staticmethod
    def validate_email(self, field):
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        if not re.match(regex, field.data):
            print("Email failed")
            raise validators.ValidationError("Email is invalid")
