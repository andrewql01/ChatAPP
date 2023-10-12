from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import LoginManager, current_user, UserMixin, login_user, logout_user, login_required

db = SQLAlchemy()

room_tag = db.Table('room_tag',
                    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
                    db.Column('room_id', db.Integer, db.ForeignKey('rooms.id'))
                    )


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    messages = relationship('Message', back_populates='user')
    rooms = relationship('Room', secondary=room_tag, back_populates='users')


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship('User', back_populates='messages')
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'))
    room = relationship('Room', back_populates='messages')
    text = db.Column(db.Text, nullable=False)


class Room(db.Model):
    __tablename__ = 'rooms'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    messages = relationship('Message', back_populates='room')
    users = relationship('User', secondary=room_tag, back_populates='rooms')


