from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    __tablename__ = 'users'

    username = db.Column(db.String(20), primary_key=True)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), unique=True)

    feedback = db.relationship('Feedback', backref='user', cascade='all, delete-orphan')

    @classmethod
    def register(cls, username, password, email, first_name, last_name):
        """Register user with hashed password & return user."""
        hashed = bcrypt.generate_password_hash(password).decode('utf8')
        return cls(
            username=username,
            password=hashed,
            email=email,
            first_name=first_name,
            last_name=last_name
        )

    @classmethod
    def authenticate(cls, username, password):
        """Validate that user exists & password is correct."""
        user = cls.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            return user
        return False

class Feedback(db.Model):
    __tablename__ = 'feedback'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    username = db.Column(db.String(20), db.ForeignKey('users.username'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)