import re

from app import db
from models import AuditLog


def weak_password(password):
    if len(password) < 5:
        return True
    if not re.search(r'\d', password):
        return True
    if not re.search(r'[a-z]', password):
        return True
    if not re.search(r'[A-Z]', password):
        return True
    if not re.search(r'[`~!@#$%^&*()_\-+=]', password):
        return True

    return False


def common_password(password):
    common_passwords = open('resources/common_pw_list').read().split('\n')
    for common_password in common_passwords:
        if common_password == password:
            return True

    return False


def add_log_entry(time_p, user_id_p, severity_p, log_type_p, message_p):
    new_log = AuditLog(time=time_p,
                      user_id=user_id_p,
                      severity=severity_p,
                      log_type=log_type_p,
                      message=message_p)

    db.session.add(new_log)
    db.session.commit()
