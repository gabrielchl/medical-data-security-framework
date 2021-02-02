import bcrypt
from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
import pyotp

from utils import weak_password, common_password

app = Flask(__name__)

app.config['SECRET_KEY'] = 'gaSM0zm4mGkiiByqcXmHCRkLPwlHrcBw'.encode('utf8')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prod.db'
db = SQLAlchemy(app)

from models import User, Patient, Staff
        
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

    new_user = User(username=username, password=password, role='Patient')
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
    
@app.route('/api/change-role', methods=['post'])
def api_change_role():
    if (
        not request.data
        or 'username' not in request.get_json()
        or 'role' not in request.get_json()
    ):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Missing data'
            }
        })
        
    if not session.get('uid'):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Not logged in'
            }
        })
    
    request_payload = request.get_json()
    username = request_payload['username']
    role = request_payload['role']
    request_user = User.query.filter_by(id=session['uid']).first()
    user = User.query.filter_by(username=username).first()
    
    if not request_user.role == "Admin":
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Not Admin'
            }
        })
        
    if role not in ['Admin', 'Regulator', 'Staff', 'Patient']:
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Role not allowed'
            }
        })
    
    if request_user == user:
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Cant change own role'
            }
        })
    
    user.role = role
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'data': {}
    })
    
@app.route('/api/add-patient-record', methods=['post'])
def api_add_patient_record():
    if (
        not request.data
        or 'name' not in request.get_json()
        or 'age' not in request.get_json()
        or 'user_id' not in request.get_json()
        or 'doctor_id' not in request.get_json()
    ):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Missing data'
            }
        })
        
    request_user = User.query.filter_by(id=session['uid']).first()
        
    if request_user.role not in ['Admin', 'Staff']:
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Insufficient permissions'
            }
        })
        
    request_payload = request.get_json()
    new_patient = Patient(name=request_payload['name'],
                    age=request_payload['age'],
                    user_id=request_payload['user_id'],
                    doctor_id=request_payload['doctor_id'])
    db.session.add(new_patient)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'data': {}
    })
    
@app.route('/api/add-staff-record', methods=['post'])
def api_add_staff_record():
    if (
        not request.data
        or 'name' not in request.get_json()
        or 'user_id' not in request.get_json()
    ):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Missing data'
            }
        })
    request_user = User.query.filter_by(id=session['uid']).first()
    
    if not request_user.role == "Admin":
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Not Admin'
            }
        })
        
    request_payload = request.get_json()
    new_staff = Staff(name=request_payload['name'],
                      user_id=request_payload['user_id'])
    db.session.add(new_staff)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'data': {}
    })
    
@app.route('/api/remove-patient-record', methods=['post'])
def api_remove_patient_record():
    if (
        not request.data
        or 'id' not in request.get_json()
    ):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Missing data'
            }
        })
        
    request_payload = request.get_json()
    staff_user = User.query.filter_by(id=session['uid']).first()
        
    if staff_user.role not in ['Admin', 'Staff']:
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Insufficient permissions'
            }
        })
    
    Patient.query.filter_by(id=request_payload['id']).delete()    
    db.session.commit()
    return jsonify({
            'status': 'success',
            'data': {
                'title': 'Patient record deleted'
            }
        })

@app.route('/api/remove-staff-record', methods=['post'])
def api_remove_staff_record():
    if (
        not request.data
        or 'id' not in request.get_json()
    ):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Missing data'
            }
        })
        
    request_user = User.query.filter_by(id=session['uid']).first() 
    if not request_user.role == "Admin":
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Not Admin'
            }
        })
        
    request_payload = request.get_json()
    
    Staff.query.filter_by(id=request_payload['id']).delete()    
    db.session.commit()
    return jsonify({
            'status': 'success',
            'data': {
                'title': 'Staff record deleted'
            }
        })
    
@app.route('/api/update-patient-record', methods=['post'])
def api_update_patient_record():
    if (
        not request.data
        or 'id' not in request.get_json()
        or 'name' not in request.get_json()
        or 'age' not in request.get_json()
        or 'user_id' not in request.get_json()
        or 'doctor_id' not in request.get_json()
    ):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Missing data'
            }
        })
        
    staff_user = User.query.filter_by(id=session['uid']).first()
        
    if staff_user.role not in ['Admin', 'Staff']:
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Insufficient permissions'
            }
        })
        
    request_payload = request.get_json()
    patient = Patient.query.filter_by(id=request_payload['id']).first()
    patient.name = request_payload['name']
    patient.age = request_payload['age']
    patient.user_id = request_payload['user_id']
    patient.doctor_id = request_payload['doctor_id']    
    db.session.commit()
    return jsonify({
            'status': 'success',
            'data': {
                'title': 'Patient record updated'
            }
        })
    
@app.route('/api/update-staff-record', methods=['post'])
def api_update_staff_record():
    if (
        not request.data
        or 'id' not in request.get_json()
        or 'name' not in request.get_json()
        or 'user_id' not in request.get_json()
    ):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Missing data'
            }
        })
        
    request_user = User.query.filter_by(id=session['uid']).first() 
    if not request_user.role == "Admin":
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Not Admin'
            }
        })
        
    request_payload = request.get_json()
    staff = Staff.query.filter_by(id=request_payload['id']).first()
    staff.name = request_payload['name']
    staff.user_id = request_payload['user_id']
    db.session.commit()
    return jsonify({
            'status': 'success',
            'data': {
                'title': 'Staff record updated'
            }
        })

@app.route ('/api/view')
def api_view():
    if not session.get('uid'):
        return jsonify({
            'status': 'fail',
            'data': {
                'title': 'Not logged in'
            }
        })    
    
    user = User.query.filter_by(id=session['uid']).first()
    
    if user.role == 'Regulator':
        all_patients = Patient.query.all()
        return jsonify({
            'status': 'success',
            'data': str(all_patients)
        })
        
    if user.role == 'Staff':
        doctor = Staff.query.filter_by(user_id=session['uid']).first()
        all_patients = Patient.query.filter_by(doctor_id=doctor.id).all()
        return jsonify({
            'status': 'success',
            'data': str(all_patients)
        })
    
    patient = Patient.query.filter_by(user_id=session['uid']).first()
    
    if patient:
        return jsonify({
        'status': 'success',
        'data': {
            'name': patient.name,
            'age': patient.age
        }
    })
    
    return jsonify({
        'status': 'fail',
        'data': {
            'title': 'No patient data found for you'
        }
    })

    # commit and push check 
    # new branch
    