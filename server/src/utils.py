import re


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

def populate_db(id, time, user_id, severity, type, message):
    
    # ----- UNCOMPLETED
    request_payload = request.get_json()
    new_log = Logs( name=request_payload['name'],
                    time=request_payload['time'],
                    user_id=request_payload['user_id'],
                    severity=request_payload['severity'],
                    log_type=request_payload['log_type'],
                    message=request_payload['message'])

    db.session.add(new_log)
    db.session.commit()
