from wtforms import Form, StringField, validators, PasswordField, SubmitField

class RegistrationForm(Form):
    username = StringField("Username",[validators.Length(min=4,max=25)],render_kw={"placeholder":"Username"})
    email = StringField("Email",[validators.Length(min=6,max=35), validators.Email(message="INVALID EMAIL ADDRESS")],render_kw={"placeholder":"Email"})
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField("Register")
class LoginForm(Form):
    username = StringField("Username",[validators.Length(min=2,max=25)],render_kw={"placeholder":"Username"})
    password = PasswordField("Password", [validators.length(min=2)],render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")