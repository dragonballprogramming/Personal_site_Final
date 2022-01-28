from flask import Flask, render_template, flash, redirect, url_for, abort
from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap
from flask_mail import Mail
import smtplib
from flask_sqlalchemy import SQLAlchemy
from flask_gravatar import Gravatar
from functools import wraps
from flask_login import login_user, LoginManager, login_required, current_user, logout_user, UserMixin
import os
from werkzeug.security import generate_password_hash, check_password_hash
from forms import ContactForm, Project, LoginForm, RegisterUserForm

# creates db
import sqlite3
# db = sqlite3.connect("projects.db")

mail = Mail()

my_email = os.environ.get('MY_EMAIL')
password = os.environ.get('EMAIL_PASSWORD')

app = Flask(__name__)
ckeditor = CKEditor(app)
Bootstrap(app)
app.secret_key = os.environ.get('SECRET_KEY')

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

#Login manager
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#loads a user when logged in
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

logged_in = False

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #if id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

class ProjectsClass(db.Model):
    __tablename__ = "projects"
    id = db.Column(db.Integer, primary_key=True)
    project_link = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    comments = db.Column(db.String(250), nullable=False)

# db.create_all()

class Users(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)

db.create_all()

@app.route('/', methods=["GET", "POST"])
def home():
    cform = ContactForm()
    my_projects = ProjectsClass.query.all()
    if cform.validate_on_submit():
        c_name = cform['name']
        c_email = cform['email']
        c_message = cform['message']
        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(user=my_email, password=password)
            connection.sendmail(
                from_addr=my_email,
                to_addrs="kchezzy88@gmail.com",
                msg=f"Subject: New Contact\n\n {c_name}, {c_email}, {c_message}"
                )
        flash("Thanks for messaging me I will get back to you as soon as possible")
        return redirect(url_for('home'))

    return render_template("index.html", form=cform, my_projects=my_projects)

@app.route("/new-project", methods=["GET", "POST"])
@admin_only
def add_new_project():
    form = Project()
    if form.validate_on_submit():
        new_post = ProjectsClass(
            project_link=form.project_link.data,
            name=form.name.data,
            comments=form.comments.data,
            )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("new-project.html", form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterUserForm()
    if form.validate_on_submit():
        email = form.email.data
        user = Users.query.filter_by(email=email).first()
        if user:
            flash("You are already signed up with this email. Login In!")
        else:
            hash_salted_pw = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = Users(
                email=form.email.data,
                password=hash_salted_pw,
                name=form.name.data,
            )
            db.session.add(new_user)
            db.session.commit()
            user = Users.query.filter_by(password=hash_salted_pw).first()
            print(user)
            login_user(user)
            return redirect(url_for('home'))
    return render_template("register.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        user = Users.query.filter_by(email=email).first()
        if user:
            hashed_pw = check_password_hash(pwhash=user.password,
                                           password=form.password.data)
            if hashed_pw:
                print(user)
                login_user(user)
                return redirect(url_for("home"))
            else:
                flash("incorrect password please try again")
        else:
            flash("This email is not in our data base please register or login with another email.")
    return render_template("login.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = ProjectsClass.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('home'))

@app.route("/projects", methods=['GET', 'POST'])
def projects():
    my_projects = ProjectsClass.query.all()
    return render_template('projects.html', my_projects=my_projects)

if __name__ == "__main__":
    app.run(debug=True)