from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
def vietnam_time():
    return datetime.utcnow() + timedelta(hours=7)
db = SQLAlchemy()
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    kdf_salt = db.Column(
        db.String(64),
        nullable=False
    )

    failed_attempts = db.Column(
        db.Integer,
        default=0
    )

    locked_until = db.Column(
        db.DateTime,
        nullable=True
    )
class PasswordEntry(db.Model):
    __tablename__ = "password_entries"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    website = db.Column(
        db.String(100),
        nullable=False
    )

    account_username = db.Column(
        db.String(100),
        nullable=False
    )

    encrypted_password = db.Column(
        db.Text,
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id")
    )
class ActivityLog(db.Model):

    __tablename__ = "activity_logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id")
    )

    action = db.Column(
        db.String(100),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=vietnam_time
    )