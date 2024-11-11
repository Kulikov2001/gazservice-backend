from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False)

    def __init__(self, username, password, role):
        self.username = username
        self.password = bcrypt.generate_password_hash(password)
        self.role = role

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class Work(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    geo = db.Column(db.String(120), nullable=False)
    work = db.Column(db.String(120), nullable=False)
    sum = db.Column(db.Float, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    photo = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, geo, work, sum, name, description, photo):
        self.geo = geo
        self.work = work
        self.sum = sum
        self.name = name
        self.description = description
        self.photo = photo