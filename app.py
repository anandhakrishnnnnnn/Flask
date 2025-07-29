from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
import random
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'anandhannn1122@gmail.com'  
app.config['MAIL_PASSWORD'] = ''     

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

# Database model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)

# Forms
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class OTPForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[InputRequired(), Length(6, 6)])
    submit = SubmitField('Verify')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(email=form.email.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['email'] = user.email
        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
        msg.body = f"Your OTP code is: {otp}"
        mail.send(msg)
        return redirect(url_for('verify_otp'))
    return render_template('register.html', form=form)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    form = OTPForm()
    if form.validate_on_submit():
        if form.otp.data == session.get('otp'):
            user = User.query.filter_by(email=session['email']).first()
            if user:
                user.is_verified = True
                db.session.commit()
                flash('Account verified. You can now login.', 'success')
                return redirect(url_for('login'))
        flash('Invalid OTP', 'danger')
    return render_template('verify_otp.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.is_verified:
                session['user_id'] = user.id
                flash('Login successful', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Please verify your account first.', 'warning')
                return redirect(url_for('verify_otp'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html',email=session['email'])

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
