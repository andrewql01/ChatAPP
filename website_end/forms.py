from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField
from wtforms.validators import DataRequired, Length

class SignInForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(8)])
    submit = SubmitField("Done")


class MessageForm(FlaskForm):
    text = StringField("", validators=[DataRequired()], render_kw={"placeholder": "Message 📨",
                                                                   'autofocus': True,
                                                                   'id': 'form'})
    submit = SubmitField("Send")