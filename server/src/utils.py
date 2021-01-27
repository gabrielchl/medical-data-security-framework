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
