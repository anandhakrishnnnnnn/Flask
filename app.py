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
app.config['MAIL_PASSWORD'] = 'wpzh udck iogx zskg'     

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)




class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)

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
    
    
def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(email, otp):
    try:
        msg = Message('Your OTP Code',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"Your OTP is: {otp}"
        mail.send(msg)
        print("OTP email sent to", email)
    except Exception as e:
        print("Email sending failed:", e)

    
    
    

@app.route('/')
def home():
    return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered!", "danger")
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        otp = generate_otp()

        new_user = User(email=form.email.data, password=hashed_password, is_verified=False)
        db.session.add(new_user)
        db.session.commit()

        session['email'] = form.email.data
        session['otp'] = otp

        send_otp(form.email.data, otp)
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

        if not user:
            flash('Email not registered. Please register first.', 'danger')
            return redirect(url_for('login'))

        if not bcrypt.check_password_hash(user.password, form.password.data):
            flash('Incorrect password. Please try again.', 'danger')
            return redirect(url_for('login'))

        if not user.is_verified:
            flash('Account not verified. Please check your email.', 'warning')
            return redirect(url_for('login'))

        session['user_id'] = user.id
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)