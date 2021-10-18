import re
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Required, Email, ValidationError, Length, EqualTo


def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<> "
    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(
                f"Character {char} is not allowed.")


def pin_check(form, field):
    if len(field.data) != 32:
        raise ValidationError('PIN must be 32 characters')


class RegisterForm(FlaskForm):
    email = StringField(validators=[Required(), Email()])
    firstname = StringField(validators=[Required(), character_check])
    lastname = StringField(validators=[Required(), character_check])
    phone = StringField(validators=[Required()])
    password = PasswordField(validators=[Required(), Length(min=6, max=12, message='Password must be between '
                                                                                   '6 and 12 characters in length.')])
    confirm_password = PasswordField(validators=[Required(), EqualTo('password', message='Both password fields '
                                                                                         'must be equal!')])
    pin_key = StringField(validators=[Required(), pin_check])
    submit = SubmitField()

    def validate_password(self, password):
        p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*?[^A-Za-z\s0-9])')
        if not p.match(self.password.data):
            raise ValidationError("Password must contain at least 1 digit, 1 lowercase, "
                                  "1 uppercase and 1 special character")

    def validate_phone(self, phone):
        p = re.compile(r'\d\d\d\d-\d\d\d-\d\d\d\d')
        if not p.match(self.phone.data):
            raise ValidationError("Phone must be of the form XXXX-XXX-XXXX")


class LoginForm(FlaskForm):
    username = StringField(validators=[Required(), Email()])
    password = PasswordField(validators=[Required()])
    pin_key = StringField(validators=[Required()])
    submit = SubmitField()
