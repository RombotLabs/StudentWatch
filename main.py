from flask import Flask, jsonify, request, abort, flash, url_for, redirect, render_template, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_BINDS'] = {
    'content': 'sqlite:///content.db'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

videos_clean = []

class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    school = db.Column(db.String(120), nullable=True)
    class_ = db.Column("class", db.String(120), nullable=True)
    role = db.Column(db.String(120), nullable=False, default="student")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Video(db.Model):
    __bind_key__ = 'content'
    __tablename__ = "Content"

    id = db.Column(db.Integer, primary_key=True)
    video = db.Column(db.String, nullable=False)
    _class_ = db.Column(db.String, nullable=False)
    _school_ = db.Column(db.String, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    expiring_date = db.Column(db.DateTime, nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username')
    email = StringField('Email')
    password = PasswordField('Password')
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Benutzername')
    password = PasswordField('Passwort')
    email = StringField('E-Mail')
    submit = SubmitField('Login')


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    user = User.query.filter_by(username=current_user.username).first()
    if user:
        print(user.class_)
    
    videos = Video.query.filter(
        Video._school_ == current_user.school,
        Video._class_ == current_user.class_,
    ).all()
    
    for v in videos:
        video_id = v.video.replace("https://www.youtube.com/watch?v=", "")
        videos_clean.append(video_id)

    return render_template('dashboard.html', name=current_user.username, video_list=videos_clean)


@app.route("/profile/<username>")
def profile(username):
    user =  User.query.filter_by(username=username).first()
    if not user:
        abort(404)

    return {
        "username": user.username,
        "role": user.role,
        "school": user.school,
        "class": user.class_,
    }

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = RegistrationForm(obj=current_user)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.password.data:
            current_user.set_password(form.password.data)
        db.session.commit()
        flash('Your settings have been updated!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('settings.html', form=form)

@app.errorhandler(404)
def not_found_error(error):
    return f'Error 404 Site not found!', 404


if __name__ == '__main__':
    app.run(debug=True)