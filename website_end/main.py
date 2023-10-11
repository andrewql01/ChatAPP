import secrets
from flask import Flask, render_template, redirect, url_for, request, jsonify, session
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField
from wtforms.validators import DataRequired, Length
from sqlalchemy import select
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor, CKEditorField
from flask_gravatar import Gravatar
from flask_login import LoginManager, current_user, UserMixin, login_user, logout_user, login_required
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from flask_cors import CORS
from models import *


app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
bootstrap = Bootstrap5(app)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chat.db"
db.init_app(app)

ckeditor = CKEditor()
ckeditor.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

socketio = SocketIO(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    use_ssl=False,
                    base_url=None)


CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


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
            session['room'] = 'main_chat'
            session['name'] = new_user.username
            return redirect(url_for('chat'))
    else:
        if form.validate_on_submit() and check_password_hash(user.password, form.password.data):
            login_user(user)
            session['room'] = 'main_chat'
            session['name'] = user.username
            return redirect(url_for('chat'))
    return render_template('index.html', form=form, current_user=current_user)


@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    form = MessageForm()
    messages = db.session.execute(select(Message)).scalars().all()
    return render_template('chat.html', form=form, messages=messages, current_user=current_user)


@socketio.on('connect')
def connect(auth):
    room = session.get('room')
    name = session.get('name')
    if room is None or session.get('name') is None:
        leave_room(room)
        return redirect(url_for('home'))
    else:
        join_room(room)
        return redirect(url_for('chat'))


@socketio.on('message')
def handle_message(data):
    room = session.get('room')
    new_message = data['message']
    message = Message(
        user=current_user,
        text=new_message,
    )
    db.session.add(message)
    db.session.commit()
    emit('message', jsonify({'data': render_template('message.html',
                                                     message=message,
                                                     current_user=current_user,
                                                     room=room),
                             'username_of_sender': data['username']}).json,
         to=room)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
