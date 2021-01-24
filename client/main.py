import requests

server_url = 'http://127.0.0.1:5000'


def signup(username, password):
    response = requests.post(
        '{}/api/signup'.format(server_url),
        json={
            'username': username,
            'password': password
        }
    )

    print(response.json())


if __name__ == '__main__':
    signup('user1', 'pw1')
