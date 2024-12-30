# Copyright (c) 2024 Vikas-06978
# Licensed under the MIT License
# Unauthorized copying of this file, via any medium, is strictly prohibited
# Written by Vikas


from dotenv import load_dotenv
import os
from app import app

load_dotenv()


app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
