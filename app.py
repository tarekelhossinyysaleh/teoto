from flask import Flask, render_template, redirect, url_for, request, flash

# from forms import RegisterForm, LoginForm
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask import Flask, request, jsonify
# from googletrans import Translator

from wtforms import StringField, SubmitField, EmailField, PasswordField, BooleanField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp, ValidationError
from wtforms.validators import DataRequired
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import login_user, current_user, logout_user, login_required
import secrets
import os
from flask_migrate import Migrate
from tokenize import String
from PIL import Image
from PIL import Image
from itsdangerous import URLSafeSerializer as Serializer
from flask_mail import Mail
from flask_mail import Message
import os

def process_image(file_path):
    with Image.open(file_path) as img:
        # Resize image maintaining aspect ratio
        img.thumbnail((800, 800))  # Example dimensions that maintain high quality
        img.save(file_path, optimize=True, quality=85)  # Save optimized image


# import json
# my_set = {1, 2, 3}
# my_list = list(my_set)  # Convert set to list
# json_data = json.dumps(my_list)
# data = {
#     'numbers': {1, 2, 3},
#     'details': {'name': 'Alice', 'age': 30}
# }

# # Convert the set inside the data structure
# if isinstance(data['numbers'], set):
#     data['numbers'] = list(data['numbers'])

# json_data = json.dumps(data)

# from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)
app.config['SECRET_KEY'] = 'DFE3RV4'
app.config['MAIL_SERVER'] = 'telhosseiny1@gmail.com'
app.config['MAIL_PORT'] = '587'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] =  os.environ.get('EMAIL_PASS')

namess = 'lllll'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{namess}'
db = SQLAlchemy(app)
app.app_context().push()
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
migrate = Migrate(app,db)
mail = Mail(app)

# Models Database#



class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(25), nullable=False)
    lname = db.Column(db.String(25), nullable=False)
    username = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(125), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False,
                           default="default.jpg")
    bio = db.Column(db.Text, nullable=True)
    bio1 = db.Column(db.Text, nullable=True)
    bio2 = db.Column(db.Text, nullable=True)
    bio3 = db.Column(db.Text, nullable=True)
    bio4 = db.Column(db.Text, nullable=True)
    bio5 = db.Column(db.Text, nullable=True)
    bio6 = db.Column(db.Text, nullable=True)
    bio7 = db.Column(db.Text, nullable=True)
    bio8 = db.Column(db.Text, nullable=True)
    bio9 = db.Column(db.Text, nullable=True)
    bio10 = db.Column(db.Text, nullable=True)

    zmax = db.Column(db.Text, nullable=True)
    password = db.Column(db.String(60), nullable=False)
    lessons = db.relationship("Lesson", backref="author", lazy=True)


    def get_reset_token(self):
        s= Serializer(app.config['SECRET_KEY'], salt='pw-reset')
        return s.dumps({'user_id':self.id})
        
    
    @staticmethod
    def verify_reset_token(token,age=3600):
        s= Serializer(app.config['SECRET_KEY'],salt='pw-reset')
        try:
            user_id = s.load(token,max_age=age)['user_id']
        except:
            return None
        return User.query.get
  
    def __repr__(self):
        return f"User('{self.fname}', '{self.lname}', '{self.username}', '{self.email}', '{self.image_file}')"
        # return f"User('{self.fname}', '{self.lname}', '{self.username}', '{self.email}', '{self.image_file}', '{self.bio}','{self.bio1}','{self.bio2}','{self.bio3}','{self.bio4}','{self.bio5}','{self.bio6}','{self.bio7}','{self.bio8}','{self.bio9}','{self.bio10}')"


class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False,
                            default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    thumbnail = db.Column(
        db.String(20), nullable=False, default="default_thumbnail.jpg"
    )
    slug = db.Column(db.String(32), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey(
        "course.id"), nullable=False)

    def __repr__(self):
        return f"Lesson('{self.title}', '{self.date_posted}')"


class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(150), nullable=False)
    icon = db.Column(db.String(20), nullable=False, default="default_icon.jpg")
    lessons = db.relationship("Lesson", backref="course_name", lazy=True)

    def __repr__(self):
        return f"Course('{self.title}')"
# FinshModels Database#
migrate = Migrate(app,db)

# FormStrted#


class RegistrationForm(FlaskForm):
    fname = StringField(
        "الاسم الأول", validators=[DataRequired(), Length(min=2, max=25)]
    )
    lname = StringField("اسم العائلة", validators=[
                        DataRequired(), Length(min=2, max=25)])
    username = StringField(
        "اسم المستخدم", validators=[DataRequired(), Length(min=2, max=25)]
    )
    email = StringField("بريد إلكتروني", validators=[DataRequired(), Email()])
    password = PasswordField(
        "كلمة المرور",
        validators=[
            DataRequired(),
            Regexp(
                "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_])[A-Za-z\d@$!%*?&_]{8,32}$"
            ),
        ],
    )
    confirm_password = PasswordField(
        "تأكيد كلمة المرور", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("التسجيل")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                "اسم المستخدم موجود بالفعل! الرجاء اختيار واحد مختلف"
            )

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                "البريد الالكتروني موجود بالفعل! الرجاء اختيار واحد مختلف")


class LoginForm(FlaskForm):
    email = StringField("بريد إلكتروني", validators=[DataRequired(), Email()])
    password = PasswordField(
        "كلمة المرور",
        validators=[
            DataRequired(),
        ],
    )
    remember = BooleanField("Remember Me")
    submit = SubmitField("دخول")


class UpdateProfileForm(FlaskForm):
    username = StringField(
        "اسم المستخدم", validators=[DataRequired(), Length(min=2, max=25)]
    )
    email = StringField("بريد إلكتروني", validators=[DataRequired(), Email()])
    bio = TextAreaField("العمر")
    bio1 = TextAreaField("المدينة: أين تعيش؟")

    bio2 = TextAreaField("مختصر السيرة الذاتية") 

    bio3 = TextAreaField("ما هي الرياضة المفضلة لك؟")

    bio4 = TextAreaField("مدرب أم لاعب")

    bio5 = TextAreaField("الإنجازات السابقة: هل لديك إنجازات رياضية سابقة؟")

    bio6 = TextAreaField("الأندية الرياضية: هل تلعب في أي أندية رياضية من قبل؟ وما هو النادي الذي تشارك فيه حاليا؟")

    bio7 = TextAreaField("التصنيف الرياضي المحلي: هل لديك تصنيف محلي في الرياضة التي تمارسها؟")

    bio8 = TextAreaField("التصنيف: هل أنت لاعب دولي؟ إذا كان الأمر كذلك، فما هو تصنيفك الدولي؟")

    bio9 = TextAreaField("المستقبل: ما هي أهدافك المستقبلية؟")
    bio10 = TextAreaField("")
    picture = FileField(
        "تعديل الصورة الخاصة بك ", validators=[FileAllowed(["jpg", "png"])]
    )
    submit = SubmitField("تعديل")

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError(
                    
                    "اسم المستخدم موجود بالفعل! الرجاء اختيار واحد مختلف"
  
                     
                )

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError(
                    "Email already exists! Please chosse a different one"
                )
            





# Routes Started
class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Regexp(
                "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_])[A-Za-z\d@$!%*?&_]{8,32}$"
            ),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Reset Password")





###  func 1 ###
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

###  func 2 ###

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_name = random_hex + f_ext
    picture_path = os.path.join(
        app.root_path, "static/user_pics", picture_name)
    output_size = (800, 800)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_name

###  func 3 ###

@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()

    return render_template('index.html', form=form)

###  func 4 ###

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(
            fname=form.fname.data,
            lname=form.lname.data,
            username=form.username.data,
            email=form.email.data,
            password=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        flash(f"Acciybt created succssfuly {form.username.data}", 'success')
        return redirect(url_for('login'))

    return render_template('register.html', 
                           title='Register',
                             form=form, )

###  func 5 ###

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('you have been logged in ', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login un succssfuly.Please checl credentials', 'danger')

    return render_template('login.html', title='LoginForm', form=form)

###  func 6 ###

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

###  func 7 ###

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    profile_form = UpdateProfileForm()
    if profile_form.validate_on_submit():
        if profile_form.picture.data:
            picture_file = save_picture(profile_form.picture.data)
            current_user.image_file = picture_file
        current_user.username = profile_form.username.data
        current_user.email = profile_form.email.data
        current_user.bio = profile_form.bio.data
        current_user.bio1 = profile_form.bio1.data
        current_user.bio2 = profile_form.bio2.data
        current_user.bio3 = profile_form.bio3.data
        current_user.bio4 = profile_form.bio4.data
        current_user.bio5 = profile_form.bio5.data
        current_user.bio6 = profile_form.bio6.data
        current_user.bio7 = profile_form.bio7.data
        current_user.bio8 = profile_form.bio8.data
        current_user.bio9 = profile_form.bio9.data
        current_user.bio10 = profile_form.bio10.data
        db.session.commit()
        flash("Your profile has been updated", "success")
        return redirect(url_for("dashboard"))
    elif request.method == "GET":
        profile_form.username.data = current_user.username
        profile_form.email.data = current_user.email
        profile_form.bio.data = current_user.bio
        profile_form.bio1.data = current_user.bio1
        profile_form.bio2.data = current_user.bio2
        profile_form.bio3.data = current_user.bio3
        profile_form.bio4.data = current_user.bio4
        profile_form.bio5.data = current_user.bio5
        profile_form.bio6.data = current_user.bio6
        profile_form.bio7.data = current_user.bio7
        profile_form.bio8.data = current_user.bio8
        profile_form.bio9.data = current_user.bio9
        profile_form.bio10.data = current_user.bio10
    image_file = url_for(
        "static", filename=f"user_pics/{current_user.image_file}")
    return render_template(
        "dashboard.html",
        title="Dashboard",
        profile_form=profile_form,
        image_file=image_file,
        
    )


###  func 8 ###


###  func 9 ###

@app.route('/search', methods=['POST'])
def search():
    search_query = request.form.get('search_query')
    results = search_items(search_query)
    return render_template('search_results.html', results=results)


###  func 10 ###

def search_items(query):
    return User.query.filter(User.username.ilike(f"%{query}%")).all()

###  func 11 ###

@app.route('/user/<username>')
def user_page(username):
    # Retrieve the user by username
    user = User.query.filter_by(username=username).first()
    if not user:
        # Handle the case where the user doesn't exist
        return "User not found", 404

    # Assuming 'image_file' is an attribute of the user model containing the filename
    image_file = url_for("static", filename=f"user_pics/{user.image_file}")

    return render_template('user_page.html', user=user, image_file=image_file)


if __name__ == '__main__':
    app.run()


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         if (
#                 form.email.data == 'tarek@gmail.com' and
#                 form.password.data == 'Pass!!word123'):
#             flash('you have been logged in ', 'success')
#             return redirect(url_for('index'))
#         else:
#             flash('Login un succssfuly.Please checl credentials', 'danger')

#     return render_template('login.html', title='LoginForm', form=form)
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message(
        "Pythonic App Password Reset Request",
        sender="YOUR EMAIL",
        recipients=[user.email],
        body=f"""To reset your password, visit the following link:
        {url_for('reset_password', token=token, _external=True)}
        
        if you did not make this request, please ignore this email.""",
    )
    mail.send(msg)



@app.route("/reset_password", methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash(
            "If this account exists, you will receive an email with instructions",
            "info",
        )
        return redirect(url_for("login"))
    return render_template("reset_request.html", title="Reset Password", form=form)



@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    user = User.verify_reset_token(token)
    if not user:
        flash("The token is invalid or expired", "warning")
        return redirect(url_for("reset_request"))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user.password = hashed_password
        db.session.commit()
        flash(f"Your password has been updated. You can now log in", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", title="Reset Password", form=form)
