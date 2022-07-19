from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, IntegerField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField
from wtforms.fields.html5 import EmailField

##WTForm

# Make A New POst
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# Login Form.
class LoginForm(FlaskForm):
    email = EmailField('Enter Your Email.', validators=[DataRequired("Please enter your email address."), Email('Invalid email address. ex.. name@gmail.com')])
    password = PasswordField('Enter your Password.', validators=[DataRequired("Password can't be empty")])
    submit = SubmitField('Let me in')

# Registration Form.
class RegistrationForm(FlaskForm):
    name = StringField('Enter Your Name.', validators=[DataRequired("Please enter your name.")])
    email = EmailField('Enter Your Email.', validators=[DataRequired("Please enter your email address."), Email('Invalid email address. ex.. name@gmail.com')])
    password = PasswordField('Enter Your Password.', validators=[DataRequired("Password can't be empty.")])
    submit = SubmitField('Sing up')


class CommentForm(FlaskForm):
    comment = CKEditorField('Comment Something.', validators=[DataRequired()])
    submit = SubmitField('Submit Comment')

class ForgotPassword(FlaskForm):
    email = StringField('Enter Your Email', validators=[DataRequired()])
    submit = SubmitField('Send OTP')

    # otp = IntegerField('Enter OTP', validators=[DataRequired()])
    # password = PasswordField('Enter Your Password', validators=[DataRequired()])
    # re_password = StringField('Retype Your Email', validators=[DataRequired()])
    # submit = SubmitField('Submit')


class ResetPassword(FlaskForm):
    otp = IntegerField('Enter OTP', validators=[DataRequired()])
    password = PasswordField('Enter Your Password', validators=[DataRequired()])
    re_password = StringField('Retype Your Email', validators=[DataRequired()])
    submit = SubmitField('Submit')