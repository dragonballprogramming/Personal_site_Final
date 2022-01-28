from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextField, TextAreaField
from wtforms.validators import DataRequired, URL, Email, input_required
from flask_ckeditor import CKEditorField

Form = FlaskForm

class ContactForm(Form):
    name = TextField("Full Name", validators=[input_required('Please enter your name.')])
    email = StringField(label='Email', validators=[DataRequired(), Email()])
    message = TextAreaField(label='Please enter a brief discription of the project')
    submit = SubmitField(label="Submit")

class Project(Form):
    project_link = TextField("Project URL", validators=[DataRequired(), URL()])
    name = StringField(label='name', validators=[DataRequired()])
    comments = TextAreaField(label='comments')
    submit = SubmitField(label="Submit")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class RegisterUserForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    name = StringField("User Name", validators=[DataRequired()])
    submit = SubmitField("Register New User")