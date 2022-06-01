from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_ckeditor import CKEditor, CKEditorField
from datetime import datetime
import yaml

app = Flask(__name__)

# Databse initalisation
data = yaml.full_load(open('data.yaml'))
app.config['SECRET_KEY'] = data['secret_key']
# Add Database
app.config['SQLALCHEMY_DATABASE_URI'] = data['database_uri']
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# Creating User Model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=True)
    username = db.Column(db.String(50), nullable=True, unique=True)
    email = db.Column(db.String(200), nullable=True, unique=True)
    password_hash = db.Column(db.String(128), nullable=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def password(self):
        raise AttributeError('password is not valid')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

#     Creating a String
def __repr__(self):
    return '<Name %r>' % self.name
# Registration Form
class UserProfile(FlaskForm):
    name = StringField("Please Enter your Name", validators=[DataRequired()])
    username = StringField("Please enter your username", validators=[DataRequired()])
    email = StringField("Please Enter your Email", validators=[DataRequired()])
    password_hash = PasswordField("password", validators=[DataRequired(),
                                                          EqualTo('password_hash2', message="Passwords must match")])
    password_hash2 = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


# Login Form
class LoginForm(FlaskForm):
    username = StringField("Please enter your username", validators=[DataRequired()])
    password = PasswordField("Please enter your Password", validators=[DataRequired()])
    submit = SubmitField("submit")

@app.route('/')
def index():
    return render_template('index.html')


# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"),404

# Internal Server Error
@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"),500

# Login Page
@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user=Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login successfully")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong Password, Please Try Again!")
        else:
            flash("User doesn't exist, please fill the form properly")
    return render_template('login.html', form=form)

# Logout function
@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash("Logged out Successfully")
    return redirect(url_for('login'))

# Dashboard Page
@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

# Add user Page
@app.route('/user/add', methods=['GET','POST'])
def add_user():
    name = None
    form = UserProfile()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_password = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(username=form.username.data, name=form.name.data, email=form.email.data,
                         password_hash=hashed_password)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.password_hash.data = ''
        flash("User added successfully")
    return render_template('add_user.html', form=form, name=name)



if (__name__ == "__main__"):
    app.run(debug=True)
