import secrets

from flask import Flask, render_template, redirect, url_for, request, jsonify, session
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor, CKEditorField
from flask_gravatar import Gravatar
from flask_login import LoginManager, current_user, UserMixin, login_user, logout_user
from flask_socketio import SocketIO, join_room, leave_room, send



app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
bootstrap = Bootstrap5(app)

db = SQLAlchemy()
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chat.db"
db.init_app(app)

ckeditor = CKEditor()
ckeditor.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

socketio = SocketIO()
socketio.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    use_ssl=False,
                    base_url=None)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    messages = relationship('Message', back_populates='user')


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship('User', back_populates='messages')
    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


class SignInForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(8)])
    submit = SubmitField("Done")


class MessageForm(FlaskForm):
    text = StringField("", validators=[DataRequired()], render_kw={"placeholder": "Message 📨",
                                                                   'autofocus': True,
                                                                   'id': 'form'})
    submit = SubmitField("Send")


@app.route('/', methods=['GET', 'POST'])
def home():
    form = SignInForm()
    username = form.username.data
    user = db.session.execute(select(User).where(User.username == username)).scalar()
    if not user:
        if form.validate_on_submit():
            hashed_salted_password = generate_password_hash(form.password.data, method='pbkdf2', salt_length=10)
            new_user = User(
                username=username,
                password=hashed_salted_password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('chat'))
    else:
        if form.validate_on_submit() and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('chat'))
    return render_template('index.html', form=form, current_user=current_user)


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    form = MessageForm()
    if request.method == "POST":
        new_message = Message(
            text=request.form['data'],
            user=current_user
        )
        db.session.add(new_message)
        db.session.commit()
        messages = db.session.execute(select(Message)).scalars().all()
        return jsonify({'data': render_template('message.html', messages=messages, current_user=current_user)})
    messages = db.session.execute(select(Message)).scalars().all()
    return render_template('chat.html', form=form, messages=messages, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)