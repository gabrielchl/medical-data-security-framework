import datetime

from app import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    password_changed = db.Column(db.Time, onupdate=datetime.datetime.now())

    def __repr__(self):
        return '<User {} {} {} {}>'.format(
            self.id, self.username, self.password, self.password_changed
        )
