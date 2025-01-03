# Copyright (c) 2024 Vikas-06978
# Licensed under the MIT License
# Unauthorized copying of this file, via any medium, is strictly prohibited
# Written by Vikas


from flask import Flask
from flask_login import LoginManager

app = Flask(__name__)

import config

import models

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

import routes

if __name__ == '__main__':
    app.run(debug=True)
