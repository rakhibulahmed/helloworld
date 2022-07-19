from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey, Table, Integer, Column, String
from sqlalchemy.ext.declarative import declarative_base

from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegistrationForm, LoginForm, CommentForm, ForgotPassword, ResetPassword
from flask_gravatar import Gravatar
from flask import abort
from functools import wraps
import smtplib
from random import random


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donghhghffzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Creating Gravatar random image
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = b'_fd5#yf2dL"F57gDf4Q8zgffddsn\dsfxefFd]/'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise, continue with the route function
        return f(*args, **kwargs)        
    return decorated_function


# Users Login Data.
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    last_logout_time = db.Column(db.String(250), nullable=True)

    posts = relationship('BlogPost', back_populates='author')
    commentss = relationship('Comment', back_populates='comment_author')


# Blog Post Database.
class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    comment_text = db.Column(db.Text, nullable=False)

    date_time = db.Column(db.String(100), nullable=False)
    post_index_id = db.Column(db.Integer, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship('User', back_populates='commentss')


db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        return render_template('index.html', all_posts=posts, name=current_user, logged_in=current_user.is_authenticated, year=date.today().strftime("%Y"))
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, year=date.today().strftime("%Y"))


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('You are already singup with that email and password, login instead!')
            return redirect(url_for('login'))
        else:
            passwd = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=10)
            nm = form.name.data
            new_user = User(
                email=form.email.data,
                name=nm.title(),
                password=passwd,
                )

            db.session.add(new_user)
            db.session.commit()

            flash(f'{nm.title().split(" ")[0]}, Your Registration was Successful, Login to your account.')
            return redirect(url_for('login'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated, year=date.today().strftime("%Y"))


@app.route('/login', methods=['POST', 'GET'])
def login():
    for_p = False
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user and check_password_hash(user.password, form.password.data):
                login_user(user)
                if current_user.id == 1:
                    flash(f'Welcome to the Admin pannel, {user.name.split(" ")[0]}')
                    return redirect(url_for('get_all_posts'))
                else:
                    flash(f'{user.name.split(" ")[0]}, you are Successfully logged in')
                    return redirect(url_for('get_all_posts'))
            else:
                for_p = True
                flash('Wrong password, try again.')
        else:
            flash("Email Doesn't exist, try again.")
                
    return render_template("login.html", for_p=for_p, form=form, logged_in=current_user.is_authenticated, year=date.today().strftime("%Y"))


@app.route('/logout')
def logout():
    flash('You are logged out.')
    time = datetime.now()
    last_logout = User.query.get(current_user.id)
    last_logout.last_logout_time = f"{date.today().strftime('%B %d, %Y')} AT {time.strftime('%I:%M:%S')}"
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    comment_data = Comment.query.all()
    time = datetime.now()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                comment_text=form.comment.data,
                date_time=f"{date.today().strftime('%B %d, %Y')} AT {time.strftime('%I:%M:%S')}",
                author_id=current_user.id,
                post_index_id=post_id
                )

            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash('Only valid users can make comments, login to make your first comment.')
            return redirect(url_for('login'))

    return render_template("post.html", lenght=len(comment_data), comments=comment_data, form=form, post=requested_post, logged_in=current_user.is_authenticated, year=date.today().strftime("%Y"))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated, year=date.today().strftime("%Y"))


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated, year=date.today().strftime("%Y"))


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
            )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, is_edit=False, logged_in=current_user.is_authenticated, year=date.today().strftime("%Y"))


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        author=post.author,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author_id = current_user.id
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated, year=date.today().strftime("%Y"))


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route('/delete-comment/<int:id><int:pst_id><int:author_id>', methods=['POST', 'GET'])
def delete_comment(id, pst_id, author_id):
    if request.method == 'GET':
        if current_user.id == 1 or current_user.id == author_id:
            com = Comment.query.get(id)
            db.session.delete(com)
            db.session.commit()
        else:
            abort(403)
    return redirect(url_for('show_post', post_id=pst_id))


@app.route('/user')
@login_required
def current_users():
    return render_template('user.html',logged_in=current_user.is_authenticated, name=current_user.name, year=date.today().strftime("%Y"))


@app.route('/forgot-password', methods=['POST', 'GET'])
def forgot_password():
    forms = ForgotPassword()
    random_otp = str(random()).split('.')[1][1:7]
    
    if forms.validate_on_submit():
        user = User.query.filter_by(email=forms.email.data).first()
        if user:
            user_index = int(str(user).split(' ')[1].replace('>', ''))
            return redirect(url_for('reset_password', user_index=user_index, otp=random_otp))
        else:
            flash("This Email doesn't exist, please enter a correct email address!")
    return render_template('forgot_password.html', form=forms)


@app.route('/reset-password/<int:user_index>/<int:otp>', methods=['POST', 'GET'])
def reset_password(user_index, otp):
    form = ResetPassword()
    if form.validate_on_submit():
        if form.otp.data != otp:
            flash('Invalid OTP')
        else:
            if form.password.data == form.re_password.data:
                if len(form.re_password.data) <= 5:
                    flash('Password must have at least 6 characters long.')

                else:
                    user = User.query.get(user_index)
                    user.password = generate_password_hash(form.re_password.data, method='pbkdf2:sha256', salt_length=10)
                    db.session.commit()
                    return redirect(url_for('login'))
            else:
                flash('Two filled of password must match')
    return render_template('reset_password.html', reset_form=form)


if __name__ == "__main__":
    app.run(debug=True)

