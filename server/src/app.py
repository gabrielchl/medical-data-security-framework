from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prod.db'
db = SQLAlchemy(app)

from models import User


@app.route('/')
def index():
    return 'all requests should be made through api endpoints.'


@app.route('/api/signup', methods=['post'])
def api_signup():
    if (not request.data
            or 'username' not in request.get_json()
            or 'password' not in request.get_json()):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Missing data'
            }
        }), 401

    request_payload = request.get_json()
    username = request_payload['username']
    password = request_payload['password']

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'data': {}
    })
