from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, EqualTo

class RegisterForm(FlaskForm):
    username = StringField('Username', 
        validators=[InputRequired(), Length(min=1, max=20)])
    password = PasswordField('Password', 
        validators=[InputRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password',
        validators=[InputRequired(), EqualTo('password', message='Passwords must match')])
    email = StringField('Email', 
        validators=[InputRequired(), Email()])
    first_name = StringField('First Name', 
        validators=[InputRequired(), Length(max=30)])
    last_name = StringField('Last Name', 
        validators=[InputRequired(), Length(max=30)])

class LoginForm(FlaskForm):
    username = StringField('Username', 
        validators=[InputRequired(), Length(min=1, max=20)])
    password = PasswordField('Password', 
        validators=[InputRequired()])

class FeedbackForm(FlaskForm):
    title = StringField('Title', 
        validators=[InputRequired(), Length(max=100)])
    content = TextAreaField('Content', 
        validators=[InputRequired()])

class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', 
        validators=[InputRequired(), Email()])

class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', 
        validators=[InputRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password',
        validators=[InputRequired(), EqualTo('password', message='Passwords must match')])