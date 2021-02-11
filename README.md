# Medical Data Security Framework

## Quick Start

### Server
1. go to `/server/src`
2. install python, and the following pip packages: flask, flask_sqlalchemy, bcrypt, pyotp, shutil
3. create database tables by running `flask shell`, `from app import db` and `db.create_all()`
4. run server by running `flask run`

### Client
1. go to `/client`
2. install the following pip packages: requests, qrcode
3. run client by running `python3 main.py`
4. check all available commands by typing in `help`

## Sources
List of common passwords: https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt
