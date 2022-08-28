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
from flask_ckeditor import CKEditor, CKEditorField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from werkzeug.utils import secure_filename
from uuid import uuid4
import os

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



####################################################################################################
#################################### Database ######################################################

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



####################################################################################################
#################################### DB relationships ##############################################

######### One-To-One #########

class Parent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    child = db.relationship("Child", backref="parent", uselist=False) ### backref is used to access the parent object from the child object ###
    ### uselist=False means that there is only one child per parent ###

class Child(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("parent.id"), nullable=False, unique=True)

    def __str__(self):
        return f"{self.id}.  {self.name} - {self.parent_id}"

@app.route('/test_OTO_relationship', methods=['GET'])
def test_OTO_relationship():

    ### used to delete any existent Parent or Child ###
    # db.session.query(Parent).delete()
    # db.session.query(Child).delete()

    parent1 = Parent(name="Parent 1")
    child1 = Child(name="Child 1", parent=parent1)
    parent2 = Parent(name="Parent 2")
    child2 = Child(name="Child 2", parent=parent2)
    parent3 = Parent(name="Parent 3")
    child3 = Child(name="Child 3", parent=parent3)
    db.session.add_all([parent1, parent2, parent3, child1, child2, child3])
    db.session.commit()
    return render_template('DB_relationships/test_OTO_relationship.html', parents=Parent.query.all())


######### One-To-Many #########

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    comments = db.relationship('Comment', backref='mypost', lazy=True) ### lazy=True is used to load the data only when it is needed ###

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))


@app.route('/test_OTM_relationship', methods=['GET'])
def test_OTM_relationship():

    ### used to delete any existent posts or comments ###
    # db.session.query(Post).delete()
    # db.session.query(Comment).delete()

    post1 = Post(title='Post The First', content='Content for the first post')
    post2 = Post(title='Post The Second', content='Content for the Second post')
    post3 = Post(title='Post The Third', content='Content for the third post')

    ### you can send either a post object or a post id ###
    comment1 = Comment(content='Comment for the first post', mypost=post1)
    comment2 = Comment(content='Comment for the second post', mypost=post2)
    comment3 = Comment(content='Another comment for the second post', post_id=2)
    comment4 = Comment(content='Another comment for the first post', post_id=1)

    

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

    ### drops and create all tables ###
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



####################################################################################################
#################################### authentecation ################################################

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



####################################################################################################
#################################### return Json for API ##############################################

@app.route('/api/today_datetime', methods=['GET'])
def api_today_datetime():
    return {"datetime": datetime.now()}
    ### just return a map and flask will automatically covert it to json ###



####################################################################################################
#################################### Pagination ##############################################

class Topics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(50), nullable=False)
    def __str__(self):
        return f"{self.id}.  {self.topic}"


@app.route('/paginate/<int:page_num>', methods=['GET'])
def paginate(page_num):

    ### used to delete any existent Topic ###
    db.session.query(Topics).delete()

    for i in range(1, 201):
        topic = Topics(topic=f"Topic {i}")
        db.session.add(topic)
    db.session.commit()

    topics = Topics.query.paginate(page = page_num, per_page = 20, error_out = True) 

    return render_template('pagination.html', topics=topics)



####################################################################################################
#################################### Global Variables ##############################################

### return a map whose keys will be available as "global" variables in the template rendering phase. ###
@app.context_processor
def inject_Post_and_User():
    return {'my_user':User(), 'myPost':Post()} ### you can use any object or pass any data ###
    ### this is used to inject the Post and User classes into the templates ###

### Template context processors work best when the data you want to use is relatively static, ###
### say configuration information that is fixed at app initialisation, cached data or things that are easy to programatically generate ###

### Because the processor is called on every render call you want to make sure it is either fast and efficient or necessary. ###

### Commonly you use it for information that is needed on every page ###



########################################################################################################
#################################### Add Rich Text Editor ##############################################

### check usage from ###
### https://flask-ckeditor.readthedocs.io/en/latest/basic.html ###

ckeditor = CKEditor(app)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    def __str__(self):
        return f"{self.id}.  {self.title}"

class BookForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = CKEditorField("Body", validators=[DataRequired()])
    submit = SubmitField("Submit")


@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    form = BookForm()
    if form.validate_on_submit():
        book = Book(title=form.title.data, content=form.content.data)
        db.session.add(book)
        db.session.commit() 
        return form.content.data
    return render_template('ckeditor.html', form=form)



########################################################################################################
#################################### Working with images ###############################################


app.config['UPLOAD_FOLDER'] = "static/uploads"

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    image = db.Column(db.String(70), nullable=False)
    def __str__(self):
        return f"{self.id}.  {self.name}"

class ProfileForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    image = FileField("Image", validators=[FileAllowed(['jpg', 'png']), FileRequired()])
    submit = SubmitField("Submit")


@app.route('/add_profile', methods=['GET', 'POST'])
def add_profile():
    form = ProfileForm()
    if form.validate_on_submit():
        image = form.image.data
        ### make sure the image name is safe ###
        image_name = secure_filename(image.filename)  
        ### generate a random name for the image ###
        image_name = str(uuid4()) + "_" + image_name  
        ### save image ###
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        image.save(f"{app.config['UPLOAD_FOLDER']}/{image_name}")
        profile = Profile(name=form.name.data, image=image_name)
        db.session.add(profile)
        db.session.commit()
        return f"<img src={app.config['UPLOAD_FOLDER']}/{image_name}>"
    return render_template('add_profile.html', form=form)
