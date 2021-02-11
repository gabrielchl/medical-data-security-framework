import re
import requests
import qrcode

server_url = 'http://127.0.0.1:5000'
s = requests.Session()


def help():
    print('help')
    print('signup <username> <password>')
    print('signin <username> <password> [otp_code]')
    print('change_pw <username> <old_password> <new_password> [otp_code]')
    print('signout')
    print('setup_otp')
    print('change_role <username> <role>')
    print('add_patient_record <name> <age> <user id> <doctor id>')
    print('add_staff_record <name> <user id>')
    print('remove_patient_record <id>')
    print('remove_staff_record <id>')
    print('update_patient_record <id> <name> <age> <user id> <doctor id>')
    print('update_staff_record <id> <name> <user id>')
    print('logs')

def signup(username, password):
    response = s.post(
        '{}/api/signup'.format(server_url),
        json={
            'username': username,
            'password': password
        }
    )

    print(response.json())


def signin(username, password, otp_code=None):
    payload = {
        'username': username,
        'password': password
    }

    if otp_code:
        payload['otp_code'] = otp_code

    response = s.post(
        '{}/api/signin'.format(server_url),
        json=payload
    )

    print(response.json())


def change_pw(username, old_password, new_password, otp_code=None):
    payload = {
        'username': username,
        'old_password': old_password,
        'new_password': new_password
    }

    if otp_code:
        payload['otp_code'] = otp_code

    response = s.post(
        '{}/api/change-pw'.format(server_url),
        json=payload
    )

    print(response.json())


def signout():
    s.get('{}/api/signout'.format(server_url))


def setup_otp():
    response = s.get('{}/api/setup-otp'.format(server_url)).json()
    print(response)
    if response['status'] == 'success':
        qrcode.make(response['data']['otp_link']).show()

def change_role(username, role):
    payload = {
        'username': username,
        'role': role
    }
    
    response = s.post(
        '{}/api/change-role'.format(server_url),
        json=payload
    )
    print(response.json())

def view():
    response = s.get('{}/api/view'.format(server_url)).json()
    print(response)
    
def add_patient_record(name, age, user_id, doctor_id):
    payload = {
        'name': name,
        'age': age,
        'user_id': user_id,
        'doctor_id': doctor_id
    }
    response = s.post(
        '{}/api/add-patient-record'.format(server_url),
        json=payload
    )
    print(response.json())
    
def add_staff_record(name, user_id):
    payload = {
        'name': name,
        'user_id': user_id
    }
    response = s.post(
        '{}/api/add-staff-record'.format(server_url),
        json=payload
    )
    print(response.json())
    
def remove_patient_record(id):
    payload = {
        'id': id
    }
    response = s.post(
        '{}/api/remove-patient-record'.format(server_url),
        json=payload
    )
    print(response.json())

def remove_staff_record(id):
    payload = {
        'id': id
    }
    response = s.post(
        '{}/api/remove-staff-record'.format(server_url),
        json=payload
    )
    print(response.json())
        
def update_patient_record(id, name, age, user_id, doctor_id):
    payload = {
        'id': id,
        'name': name,
        'age': age,
        'user_id': user_id,
        'doctor_id': doctor_id
    }
    response = s.post(
        '{}/api/update-patient-record'.format(server_url),
        json=payload
    )
    print(response.json())
    
def update_staff_record(id, name, user_id):
    payload = {
        'id': id,
        'name': name,
        'user_id': user_id
    }
    response = s.post(
        '{}/api/update-staff-record'.format(server_url),
        json=payload
    )
    print(response.json())        
        
def logs():
    response = s.get('{}/api/logs'.format(server_url)).json()
    print(response)

class Command:
    def __init__(self, name, num_argument, function):
        self.name = name
        self.num_argument = num_argument
        self.function = function

commands = [
    Command('help', 0, help),
    Command('signup', 2, signup),
    Command('signin', 2, signin),
    Command('change_pw', 3, change_pw),
    Command('signout', 0, signout),
    Command('setup_otp', 0, setup_otp),
    Command('change_role', 2, change_role),
    Command('view', 0, view),
    Command('add_patient_record', 4,add_patient_record),
    Command('add_staff_record', 2,add_staff_record),
    Command('remove_patient_record', 1,remove_patient_record),
    Command('remove_staff_record', 1,remove_staff_record),
    Command('update_patient_record', 5,update_patient_record),
    Command('update_staff_record', 3,update_staff_record),
    Command('logs', 0, logs)
]


if __name__ == '__main__':
    while True:
        input_command = re.split(r'\s+', input('> ').strip())
        if input_command[0] == 'exit':
            break
        for command in commands:
            if command.name == input_command[0]:
                if command.num_argument == 0:
                    command.function()
                elif len(input_command) - 1 >= command.num_argument:
                    command.function(*input_command[1:])
                else:
                    print('Expecting {} arguments for the command {}.'
                          .format(command.num_argument, command.name))
