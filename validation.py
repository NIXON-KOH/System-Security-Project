import re
from wtforms import StringField, validators, PasswordField, SubmitField, BooleanField, DecimalField, FileField
from flask_wtf import FlaskForm, RecaptchaField


class LoginForm(FlaskForm):
    username = StringField("username",[validators.Length(min=2,max=25)],render_kw={"placeholder":"Username"})
    password = PasswordField("password", [validators.length(min=2)],render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")
    recaptcha = RecaptchaField()

class RegistrationForm(FlaskForm):
    username = StringField("username")
    email = StringField("email")
    password = PasswordField('password')
    submit = SubmitField("Register")
    recaptcha = RecaptchaField()

    def validate_password(self, field):
        if re.search('[0-9]',field.data) is None:
            raise validators.ValidationError("Password does not include int")
        elif re.search('[A-Z]',field.data) is None:
            raise validators.ValidationError("Password does not include uppercase")
        elif re.search('[a-z]',field.data) is None:
            raise validators.ValidationError("Password does not include Lowercase")
        elif not (8 < len(field.data) < 50):
            raise validators.ValidationError("Password does not meet length")


    def validate_email(self, field):
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        if not re.match(regex, field.data):
            print("Email failed")
            raise validators.ValidationError("Email is invalid")
        
class Totpform(FlaskForm):
    totp = StringField("totp")
    submit = SubmitField("submit")

class addroom(FlaskForm):
    name = StringField("name")
    cost = DecimalField("cost")
    availability = BooleanField("availability")
    smoking = BooleanField("smoking")
    files = FileField("file")
    submit = SubmitField("submit")

class delroom(FlaskForm):
    roomno = SubmitField("submit")