from flask import Flask, render_template, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate # for database migration (commit changes when editing the db)
from datetime import datetime

### run flask app ###
# in terminal: 
#   1. flask --app yourFlaskFile.py run  
#####################
### !!! Note !!! ###
# you can ignore writing the --app parameter by seeting environmental variables

app = Flask(__name__)

### secret key ###
app.config["SECRET_KEY"] = "mysecretkey"


### create a simple route ###
@app.route('/')
def index():
    return render_template('index.html')

### create a route + passing data in url ###
@app.route('/user/<name>')
def user(name):
    return f"<h1>Hello {name}</h1>"

### create a 404 error handler route ###
@app.errorhandler(404)
def page_not_found(e):
    return "Page not found"

### create a form class ###
class MyForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Submit")

### create a form page route ###
@app.route('/form', methods=['GET', 'POST'])
def form():
    name = None
    form = MyForm()
    if form.validate_on_submit():
        flash("Form Submitted Successfully") ### flash a message ###
        name = form.name.data
        return render_template("welcomeForm.html", name=name)
    return render_template('welcomeForm.html', form=form)


### Add SQLite Database ###
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
### Initialize The Database ###
db = SQLAlchemy(app)
### Migrate The Database ###
migrate = Migrate(app, db) # for database migration
### Create Database Model ###
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    favorite_color = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __str__(self) -> str:
        return f"{self.id}.  {self.name} - {self.email} - {self.favorite_color}"

###### create tables ######
# in termenal:
#   1. winpty python
#   2. from hello import db
#   3. db.create_all()
###########################
###### DB Migration (use the following commands to commit changes when editing the DB structure) #######
# in terminal:
#   1. flask --app yourFlaskFile.py db init      (create the database or enable migrations if the database already exists)
#   2. flask --app yourFlaskFile.py db migrate -m "comment"   (create the migration file)
#   3. flask --app yourFlaskFile.py db upgrade   (apply the migration to the database)
###########################

### create a form class ###
class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    favorite_color = StringField("Favorite Color")
    submit = SubmitField("Submit")



### create a form page route ###
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            user = Users(name=form.name.data, email=form.email.data, favorite_color=form.favorite_color.data)
            db.session.add(user)
            db.session.commit() 
        name = form.name.data
        form.name.data = ""
        form.email.data = ""
        form.favorite_color.data = ""
        flash("User Added Successfully") ### flash a message ###
    
    myUsers = Users.query.order_by(Users.date)
    return render_template('add_user.html', form=form, name=name, myUsers=myUsers)

### update user by id ###
@app.route('/user/update/<int:id>', methods=['GET', 'POST'])
def update_user(id):
    user = Users.query.get_or_404(id)
    form = UserForm()
    if request.method == "POST": ### or use form.validate_on_submit(): ###
        user.name = request.form["name"]
        user.email = request.form["email"]
        user.favorite_color = request.form["favorite_color"]
        try:
            db.session.commit()
            flash("User Updated Successfully")
            return render_template('update_user.html', form=form, user=user)
        except:
            flash("Error Updating User")
            return render_template('update_user.html', form=form, user=user)
    else:
        return render_template('update_user.html', form=form, user=user)