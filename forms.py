
# from flask_wtf import FlaskForm
# from wtforms import StringField, SubmitField, EmailField, PasswordField, BooleanField
# from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp, ValidationError
# from wtforms.validators import DataRequired
# from app import User


# class RegisterForm(FlaskForm):
#     fname = StringField('First Name',
#                         validators=[
#                             DataRequired(), Length(min=2, max=25)
#                         ]
#                         )
#     lname = StringField('Last name', validators=[
#                         DataRequired(), Length(min=2, max=25)])
#     username = StringField('UserName', validators=[
#                            DataRequired(), Length(min=2, max=25)])
#     email = StringField('Email', validators=[DataRequired(), Email()])
#     password = PasswordField('Password', validators=[DataRequired(),
#                                                      Regexp(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$")])

#     confirm_password = PasswordField('confirm_password', validators=[
#                                      DataRequired(), EqualTo('password')])
#     submit = SubmitField('Sing Up')

#     def validate_username(self, username):
#         user = User.query.filter_by(username=username.data).first()
#         if user:
#             raise ValidationError(
#                 'Username already exists! Please chosse a different one')

#     def validate_email(self, email):
#         user = User.query.filter_by(email=email.data).first()
#         if user:
#             raise ValidationError(
#                 'Username already exists! Please chosse a different one')


# class LoginForm(FlaskForm):
#     email = StringField('Email', validators=[DataRequired(), Email()])
#     password = PasswordField('Password', validators=[DataRequired()])

#     remember = BooleanField('Remember Me')
#     submit = SubmitField('Sing Up')
