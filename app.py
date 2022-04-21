from email.policy import default
import bcrypt
from flask import Flask, redirect, render_template, url_for, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import sys

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///haste.db'
app.config['SECRET_KEY'] = "tempfornow"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class user(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable = False)
    password = db.Column(db.String(80), nullable = False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

class RegisterForm(FlaskForm):
    username = StringField(validators=[ InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[ InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = user.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError( 'That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[ InputRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[ InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Log in')


@app.route('/')
def index():
    return render_template("home.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        print('Hello !', form.password.data, file=sys.stderr)
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = user(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@login_manager.user_loader
def load_user(user_id):
    return user.query.get(int(user_id))

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return render_template("home.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_info = user.query.filter_by(username=form.username.data).first()
        if user_info:
            login_user(user_info)
            return render_template("home.html", user=user_info)
    return render_template("login.html", form=form)

@app.route('/news', methods=['GET', 'POST'])
def news():
     return render_template("news.html")

if __name__ == "__main__":
    app.run(debug=True)