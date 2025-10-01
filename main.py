from flask import Flask, jsonify, request, abort, flash, url_for, redirect, render_template, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField
from urllib.parse import urlparse, parse_qs

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

class VideoForm(FlaskForm):
    video_url = StringField('YouTube URL')
    target_class = StringField('Klasse')
    target_school = StringField('Schule')
    expiring_date = DateField('Ablaufdatum (YYYY-MM-DD)', format='%Y-%m-%d')
    submit = SubmitField('Video eintragen')


def extract_video_id(url: str) -> str:
    """Extract the YouTube video ID from a URL or return None if invalid."""
    if not url:
        return None

    parsed = urlparse(url)

    # Standard: https://www.youtube.com/watch?v=VIDEOID
    if parsed.hostname in ["www.youtube.com", "youtube.com"]:
        if parsed.path == "/watch":
            query = parse_qs(parsed.query)
            return query.get("v", [None])[0]

        # Embed-Links
        if parsed.path.startswith("/embed/"):
            return parsed.path.split("/embed/")[1]

    # Short links: https://youtu.be/VIDEOID
    if parsed.hostname == "youtu.be":
        return parsed.path.lstrip("/")

    # Falls schon nur die ID gespeichert ist
    if len(url) == 11:
        return url

    return None


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
    videos = Video.query.filter(
        Video._school_ == current_user.school,
        Video._class_ == current_user.class_,
        (Video.expiring_date == None) | (Video.expiring_date >= datetime.utcnow())
    ).all()

    videos_clean = []
    for v in videos:
        video_id = extract_video_id(v.video)
        print(f"RAW: {v.video} -> ID: {video_id}")  # Debug
        if video_id:
            videos_clean.append(video_id)

    return render_template('dashboard.html', 
                           name=current_user.username,
                           role=current_user.role, 
                           video_list=videos_clean)

@app.route('/add_video', methods=['GET', 'POST'])
@login_required
def add_video():
    if current_user.role != 'teacher':
        abort(403)  # Zugriff nur für Lehrer

    form = VideoForm()
    if form.validate_on_submit():
        video_id = extract_video_id(form.video_url.data)
        if not video_id:
            flash('Ungültige YouTube-URL!', 'danger')
            return render_template('add_video.html', form=form)

        new_video = Video(
            video=video_id,
            _class_=form.target_class.data,
            _school_=form.target_school.data,
            creation_date=datetime.utcnow(),
            expiring_date=form.expiring_date.data
        )
        db.session.add(new_video)
        db.session.commit()
        flash('Video erfolgreich eingetragen!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_video.html', form=form)


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