import bcrypt
from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
import pyotp

from utils import weak_password, common_password

app = Flask(__name__)

app.config['SECRET_KEY'] = 'gaSM0zm4mGkiiByqcXmHCRkLPwlHrcBw'.encode('utf8')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prod.db'
db = SQLAlchemy(app)

from models import User


@app.route('/')
def index():
    return 'all requests should be made through api endpoints.'


@app.route('/api/signup', methods=['post'])
def api_signup():
    if (
        not request.data
        or 'username' not in request.get_json()
        or 'password' not in request.get_json()
    ):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Missing data'
            }
        })

    request_payload = request.get_json()
    username = request_payload['username']
    password = request_payload['password']

    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Username occupied'
            }
        })

    if weak_password(password):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Password too weak. The Password should include at least one number, lowercase and uppercase letter and special character. It should also be at least 5 characters in length.'
            }
        })

    if common_password(password):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Common password used. Please choose a more unique password'
            }
        })

    password = bcrypt.hashpw(str.encode(password),
                             bcrypt.gensalt())

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'data': {}
    })


@app.route('/api/signin', methods=['post'])
def api_signin():
    if (
        not request.data
        or 'username' not in request.get_json()
        or 'password' not in request.get_json()
    ):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Missing data'
            }
        })

    request_payload = request.get_json()
    username = request_payload['username']

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(str.encode(request_payload['password']),
                               user.password):
        if user.otp_secret:
            if 'otp_code' not in request_payload:
                return jsonify({
                    'status': 'fail',
                    'data': {
                        'title': 'Missing OTP code'
                    }
                })

            if pyotp.TOTP(user.otp_secret).now() != request_payload['otp_code']:
                return jsonify({
                    'status': 'fail',
                    'data': {
                        'title': 'Failed OTP challenge'
                    }
                })

        session['uid'] = user.id
        return jsonify({
            'status': 'success',
            'data': {}
        })

    return jsonify({
        'status': 'fail',
        'data': {
            'title': 'Wrong credentials'
        }
    })


@app.route('/api/change-pw', methods=['post'])
def api_change_pw():
    if (
        not request.data
        or 'username' not in request.get_json()
        or 'old_password' not in request.get_json()
        or 'new_password' not in request.get_json()
    ):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Missing data'
            }
        })

    request_payload = request.get_json()
    username = request_payload['username']

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(
        str.encode(request_payload['old_password']),
        user.password
    ):

        if user.otp_secret:
            if 'otp_code' not in request_payload:
                return jsonify({
                    'status': 'fail',
                    'data': {
                        'title': 'Missing OTP code'
                    }
                })

            if pyotp.TOTP(user.otp_secret).now() != request_payload['otp_code']:
                return jsonify({
                    'status': 'fail',
                    'data': {
                        'title': 'Failed OTP challenge'
                    }
                })

        new_password = request_payload['new_password']

        if weak_password(new_password):
            return jsonify({
                'status': 'fail',
                'data': {
                    'title': 'Password too weak. The Password should include at least one number, lowercase and uppercase letter and special character. It should also be at least 5 characters in length.'
                }
            })

        if common_password(new_password):
            return jsonify({
                'status': 'fail',
                'data': {
                    'title': 'Common password used. Please choose a more unique password'
                }
            })

        user.password = bcrypt.hashpw(
            str.encode(new_password),
            bcrypt.gensalt()
        )
        db.session.commit()
        return jsonify({
            'status': 'success',
            'data': {}
        })

    return jsonify({
        'status': 'fail',
        'data': {
            'title': 'Wrong credentials'
        }
    })


@app.route('/api/signout')
def api_signout():
    session.clear()
    return jsonify({
        'status': 'success',
        'data': {}
    })


@app.route('/api/setup-otp')
def api_setup_otp():
    if not session.get('uid'):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Not logged in'
            }
        })

    otp_secret = pyotp.random_base32()
    user = User.query.filter_by(id=session['uid']).first()
    user.otp_secret = otp_secret
    db.session.commit()

    otp_link = pyotp.totp.TOTP(otp_secret).provisioning_uri(name='scc363gp9@lancaster.ac.uk', issuer_name='Medical Data Security Framework Prototype')
    return jsonify({
        'status': 'success',
        'data': {
            'otp_link': otp_link
        }
    })
