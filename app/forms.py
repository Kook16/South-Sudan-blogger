from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_wtf.file import FileAllowed
from app.models import User
from flask_login import current_user
from wtforms import ValidationError


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('Sign up')

    def validate_username(form, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username is already in use. Please choose a different one.')

    def validate_email(form, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email is already in use. Please choose a different one.')
    

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AddPost(FlaskForm):
    title =StringField('Title', validators=[DataRequired()])
    content = TextAreaField(validators=[DataRequired()])
    submit = SubmitField('Post')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')

class ResetPassword(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('Reset Password')

class ResetConfirmationLink(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Resend')


class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    bio = TextAreaField('Bio', validators=[Length(max=500)])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'])])
    submit = SubmitField('Update')

    def validate_username(self, field):
        user = User.query.filter_by(username=field.data).first()
        if user and user.id != current_user.id:
            raise ValidationError('Username is already in use. Please choose a different one.')

class EditPostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Update')


class MessageForm(FlaskForm):
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')
