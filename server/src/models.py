from app import db


class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('staff.id'))

    def __repr__(self):
        return '<Patient {} {} {} {} {}>'.format(self.id, self.name, self.age, self.user_id, self.doctor_id)


class Staff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Staff {} {} {}>'.format(self.id, self.name, self.user_id)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(80), nullable=False)
    otp_secret = db.Column(db.String(80))

    def __repr__(self):
        return '<User {} {} {}>'.format(self.id, self.username, self.role)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.String(80), nullable=False)
    user_id = db.Column(db.String(80))
    severity = db.Column(db.String(80), nullable=False)
    log_type = db.Column(db.String(80), nullable=False)
    message = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return '<AuditLog {} {} {} {} {} {}>'.format(self.id, self.time, self.user_id, self.severity, self.log_type, self.message)
