from flask_wtf import FlaskForm
from wtforms import (BooleanField, EmailField, IntegerField, PasswordField,
                     StringField, SubmitField)
from wtforms.validators import (DataRequired, Email, InputRequired, Length,
                                Regexp)


class LoginForm(FlaskForm):
    email = EmailField("Email",  validators=[
        InputRequired(), Email("Please enter your email address.")], render_kw={"placeholder": "Email"})
    password = PasswordField("Password", validators=[
                             InputRequired()], render_kw={"placeholder": "Password"})
    show_password = BooleanField('Show password', id='check')
    submit = SubmitField('SIGN IN')


class RegisterForm(FlaskForm):
    email = EmailField("Email",  validators=[
        InputRequired(), Email("Please enter your email address.")], render_kw={"placeholder": "Email"})
    name = StringField("Name",  validators=[InputRequired(),
                                            Length(min=2, max=30)], render_kw={"placeholder": "Name"})
    phone = IntegerField("Phone", validators=[DataRequired(), Regexp(
        '^[0-9]{10,12}$')], render_kw={"placeholder": "Phone"})
    address = StringField("Address",  validators=[InputRequired()], render_kw={
                          "placeholder": "Address"})
    password = PasswordField("Password", validators=[InputRequired()], render_kw={
        "placeholder": "Password"}, id="password")
    show_password = BooleanField('Show password', id='check')
    submit = SubmitField('SIGN UP')
