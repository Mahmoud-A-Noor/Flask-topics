from email.headerregistry import Address
from msilib.sequence import tables
from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate # for database migration (commit changes when editing the db)
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user ### for authentication porpuses

### run flask app ###
# in terminal: 
#   1. flask --app yourFlaskFile.py run  
#####################
### !!! Note !!! ###
# you can ignore writing the --app parameter in all commands by setting environmental variables:
#   1. export FLASK_APP=yourFlaskFile.py
#   2. export FLASK_ENV=development
#####################

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
    description = StringField("Description", validators=[DataRequired()], widget=TextArea())
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
    return render_template('welcomeForm.html', form=form) ### make sure to pass ALL and ONLY used/required parameters otherwise page will not be rendered as expected and no error will appear ###

#################################### Database ############################################33

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
    password_hash = db.Column(db.String(256))

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")
        ### using this approach we can set password attribute but we won't be able to access it ###
    
    # return self.password_hash # this will return the password hash which will be used to compare passwords
    # return self.password # this will raise an error because we can only set password attribute, we can't access it
    
    @password.setter ### by doing this we create the password_hash on setting the password attribute value Ex. user2.password="my password" ###
    def password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256') ### generate a password hash ###
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password) ### return True if the entered password has the same hash as the stored password ###


    def __str__(self) -> str:
        return f"{self.id}.  {self.name} - {self.email} - {self.favorite_color} - {self.password_hash}"

###### create tables ######
# in termenal:
#   1. winpty python
#   2. from hello import db
#   3. db.create_all()
###########################
###### DB Migration (use the following commands to commit changes when editing the DB structure) #######
# in terminal:
#   1. flask --app yourFlaskFile.py db init      (create the database or enable migrations if the database already exists)(Used for the first time)
#   2. flask --app yourFlaskFile.py db migrate -m "comment"   (create the migration file)
#   3. flask --app yourFlaskFile.py db upgrade   (apply the migration to the database)
###########################

### create a form class ###
class UsersForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    favorite_color = StringField("Favorite Color")
    password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo("password_hash2", message="Passwords must match")])
    password_hash2 = PasswordField("Confirm Password", validators=[DataRequired()]) ### this field dosn't exsists in DB, it is used just added in the form to confirm password ###
    submit = SubmitField("Submit")



### create add user route ###
@app.route('/add/user', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UsersForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            user = Users(name=form.name.data, email=form.email.data, favorite_color=form.favorite_color.data, password=form.password_hash.data)
            db.session.add(user)
            db.session.commit() 
        name = form.name.data
        form.name.data = ""
        form.email.data = ""
        form.favorite_color.data = ""
        form.password_hash.data = ""
        form.password_hash2.data = ""
        flash("User Added Successfully") ### flash a message ###
    
    myUsers = Users.query.order_by(Users.date)
    return render_template('add_user.html', form=form, myUsers=myUsers)

### update user by id ###
@app.route('/update/user/<int:id>', methods=['GET', 'POST'])
def update_user(id):
    user = Users.query.get_or_404(id)
    form = UsersForm()
    if request.method == "POST": ### or use form.validate_on_submit(): ###
        user.name = request.form["name"]
        user.email = request.form["email"]
        user.favorite_color = request.form["favorite_color"]
        try:
            db.session.add(user) ### optional
            db.session.commit()
            flash("User Updated Successfully")
            return render_template('update_user.html', form=form, user=user)
        except:
            flash("Error Updating User")
            return render_template('update_user.html', form=form, user=user)
    else:
        return render_template('update_user.html', form=form, user=user)

### delete user by id ###
@app.route('/delete/user/<int:id>', methods=['GET', 'POST'])
def delete_user(id):
    user = Users.query.get_or_404(id)
    form = UsersForm()
    if request.method == "POST": ### or use form.validate_on_submit(): ###
        try:
            db.session.delete(user)
            db.session.commit()
            flash("User Deleted Successfully")
            return render_template('add_user.html', form=form, name=None)
        except:
            flash("Error Deleting User")
            return render_template('delete_user.html', form=form, user=user)
    else:
        return render_template('delete_user.html', form=form, user=user, id=user.id)


#################################### return Json for API ############################################33

@app.route('/api/today_datetime', methods=['GET'])
def api_today_datetime():
    return {"datetime": datetime.now()}
    ### just return a map and flask will automatically covert it to json ###

#################################### authentecation ############################################33

### initializing login manager ###
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' ### login page (@loggin_required redirect to this page) ###

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) ### return user object if user_id is found in the database ###
    ### the User is the below class ###

######### create class user for authentication explanation #########
class User(db.Model, UserMixin): ### UserMixin is a class that comes with flask-login contains default implementation of some methods like is_authenticated, ... ###
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(256))

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")
    
    
    @password.setter 
    def password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256') 
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password) 
    
    def __str__(self):
        return f"{self.id}.  {self.user_name} - {self.email} - {self.password_hash}"

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

class CreateUserForm(FlaskForm):
    user_name = StringField("User Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), EqualTo("password2", message="Passwords must match")])
    password2 = PasswordField("Confirm Password", validators=[DataRequired()]) ### this field dosn't exsists in DB, it is used just added in the form to confirm password ###
    submit = SubmitField("Submit")

@app.route('/CreateUser', methods=['GET', 'POST'])
def CreateUser():
    form = CreateUserForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            user = User(user_name=form.user_name.data, email=form.email.data, password=form.password.data)
            db.session.add(user)
            db.session.commit() 
            flash("User Added Successfully")

            form.user_name.data = ""
            form.email.data = ""
            form.password.data = ""
            form.password2.data = ""
            return render_template('authentication/create_user_form.html', form=form)
        else:
            flash("User Already Exists")
            return render_template('authentication/create_user_form.html', form=form)

    if form.password.data != form.password2.data and form.password.data != None:
        flash("Error Passwords must match")
        return render_template('authentication/create_user_form.html', form=form)    
    
    return render_template('authentication/create_user_form.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.verify_password(form.password.data):
                login_user(user)
                return redirect(url_for('profile'))
            else:
                flash("Wrong Password")
                return render_template('authentication/user_login_form.html', form=form)
        else:
            flash("This Email Doesn't Exists")
            return render_template('authentication/user_login_form.html', form=form)
    return render_template('authentication/user_login_form.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    return render_template('authentication/profile.html')


@app.route('/show_users', methods=['GET'])
def show_users():
    users = User.query.all()
    return render_template('authentication/show_users.html', users=users)


#################################### DB relationships ############################################33

######### One-To-One #########




######### One-To-Many #########

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    comments = db.relationship('Comment', backref='mypost', lazy=True) ### lazy=True is used to load the data only when it is needed ###
    ### mypost is a dummy name used when you pass an object instead of id when creating a Comment  ###

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id')) ### foreign key is used to link the tables ###


@app.route('/test_OTM_relationship', methods=['GET'])
def test_OTM_relationship():
    post1 = Post(title='Post The First', content='Content for the first post')
    post2 = Post(title='Post The Second', content='Content for the Second post')
    post3 = Post(title='Post The Third', content='Content for the third post')

    ### you can send either a post object or a post id ###
    comment1 = Comment(content='Comment for the first post', mypost=post1)
    comment2 = Comment(content='Comment for the second post', mypost=post2)
    comment3 = Comment(content='Another comment for the second post', post_id=2)
    comment4 = Comment(content='Another comment for the first post', post_id=1)

    ### used to delete any existent pot or comment ###
    # db.session.query(Post).delete()
    # db.session.query(Comment).delete()

    db.session.add_all([post1, post2, post3])
    db.session.add_all([comment1, comment2, comment3, comment4])
    ### you can add all objects in one line ###
    # db.session.add_all([post1, post2, post3, comment1, comment2, comment3, comment4])

    db.session.commit()
    return render_template('DB_relationships/test_OTM_relationship.html', posts=Post.query.all())



######### Many-To-Many #########

user_channel = db.Table('user_channel',
    db.Column('follower_id', db.Integer, db.ForeignKey('follower.id')),
    db.Column('channel_id', db.Integer, db.ForeignKey('channel.id'))
) ### this will create another table containing the primary key of both tables Follower and Channel ###


class Follower(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    following = db.relationship('Channel', secondary=user_channel, backref='followers')


class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))

    def __str__(self) -> str:
        return self.name + "==>" + str(self.id)


@app.route('/test_MTM_relationship', methods=['GET'])
def test_MTM_relationship():

    # db.drop_all()
    # db.create_all()

    follower1 = Follower(name='Follower 1')
    follower2 = Follower(name='Follower 2')
    follower3 = Follower(name='Follower 3')
    channel1 = Channel(name='Channel 1')
    channel2 = Channel(name='Channel 2')
    channel3 = Channel(name='Channel 3')
    follower1.following.append(channel1)
    follower1.following.append(channel2)
    follower2.following.append(channel1)
    follower2.following.append(channel3)
    follower3.following.append(channel2)
    follower3.following.append(channel3)
    db.session.add_all([follower1, follower2, follower3, channel1, channel2, channel3])
    db.session.commit()
    user_channel_data = db.session.query(Follower.name, Channel.name).join(Channel, Follower.following).all() ### get all the data from user_channel table ###
    return render_template('DB_relationships/test_MTM_relationship.html', followers=Follower.query.all(), user_channel_data=user_channel_data)




