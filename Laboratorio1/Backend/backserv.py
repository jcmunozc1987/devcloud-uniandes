#!/usr/bin/python
# -*- coding: ascii -*-
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
import json, os, signal
from logging import exception
from  werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///task.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'DevCloud24.'
db = SQLAlchemy(app)

# Modelos
class User(db.Model):
    id = db.Column('id', db.Integer, primary_key = True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    #tasks = db.relationship('Task', backref='user', lazy=True)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def serialize (self):
        return {
            "id":self.id,
            "username":self.username ,
            "password":self.password
            }
   
class Category(db.Model):
    id = db.Column('id', db.Integer, primary_key = True)
    name = db.Column(db.String(50), unique=True,nullable=False)
    description = db.Column(db.String(200))

    def __init__(self, name, description):
        self.name = name 
        self.description = description
    
    def serialize (self):
        return {
            "id":self.id,
            "name":self.name ,
            "description":self.description
            }

class Task(db.Model):
    id = db.Column('task_id', db.Integer, primary_key = True)
    text = db.Column(db.String(200), nullable=False)
    creation_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    due_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='Sin Empezar')
    category_id = db.Column(db.Integer,  nullable=False)
    user_id = db.Column(db.Integer,  nullable=False)

    def __init__(self, text, creation_date,due_date,status,category_id,user_id):
        self.text = text
        self.creation_date = creation_date
        self.due_date = due_date
        self.status = status
        self.category_id = category_id
        self.user_id = user_id

    def serialize (self):
        return {
            "id":self.id,
            "text":self.text ,
            "creation_date":self.creation_date,
            "due_date":self.due_date ,
            "status":self.status,
            "category_id":self.category_id ,
            "user_id":self.user_id
            }

# JWT Configuración
# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            #return jsonify({'message' : data['public_id'] }), 401
            
            current_user = User.query\
                .filter_by(id = data['public_id'])\
                .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users context to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated
  
 
# route for logging user in
@app.route('/login', methods =['POST'])
def login():
    # creates dictionary of form data
    auth = request.get_json()
    if not auth or not auth['username'] or not auth['password']:
        # returns 401 if any username or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
  
    user = User.query\
        .filter_by(username = auth['username'])\
        .first()
  
    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify, user not exist',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
  
    if check_password_hash(user.password, auth['password']):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': user.id,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])
  
        return make_response(jsonify({'token' : jwt.decode(token,app.config['SECRET_KEY'], algorithms=["HS256"])}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify, incorrect pass',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )
  
# signup route
@app.route('/signup', methods =['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.get_json()
  
    # gets username and password
    username= data['username']
    password = data['password']
  
    # checking for existing user
    user = User.query\
        .filter_by(username = username)\
        .first()
    if not user:
        # database ORM object
        user = User(
            username = username,
            password = generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()
  
        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


#####################################

@app.route('/getusers', methods=['POST'])
@token_required
def get_users(current_user):
    try:
        users = User.query.all()
        usersArr = [user.serialize() for user in users]
        return jsonify(usersArr), 200
    except Exception:
        exception("[SERVER]-> Ha ocurrido un error")
        return jsonify({'message': 'Ha ocurrido un error'}), 500
    
@app.route('/newcategory', methods=['POST'])
@token_required
def new_category(current_user):
    data = request.get_json()
    try:
        new_category = Category(name=data['name'], description=data['description'])
        db.session.add(new_category)
        db.session.commit()
        return jsonify({'message': 'Categoría creada'}), 201
    except Exception:
        exception("[SERVER]-> Ha ocurrido un error")
        return jsonify({'message': 'Ha ocurrido un error'}), 500

@app.route('/getcategories', methods=['POST'])
@token_required
def get_categories(current_user):
    try:
        categories = Category.query.all()
        categoriesArr = [category.serialize() for category in categories]
        return jsonify(categoriesArr), 200
    except Exception:
        exception("[SERVER]-> Ha ocurrido un error")
        return jsonify({'message': 'Ha ocurrido un error'}), 500

@app.route('/newtask', methods=['POST'])
@token_required
def new_task(current_user):
    data = request.get_json()
    try:
        if data['due_date'] =='': data['due_date'] = datetime(1990, 1, 1, 0, 0, 0)
        new_task = Task(text=data['text'], 
                        creation_date=datetime.utcnow(),
						due_date=data['due_date'], 
                        status=data['status'],
						category_id=data['category_id'], 
                        user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()
        return jsonify({'message': 'Tarea creada'}), 201
    except Exception:
        exception("[SERVER]-> Ha ocurrido un error")
        return jsonify({'message': 'Ha ocurrido un error'}), 500


@app.route('/gettasks', methods=['POST'])
@token_required
def get_tasks(current_user):
    try:
        tasks = Task.query.filter_by(user_id = current_user.id).all()
        tasksArr = [task.serialize() for task in tasks]
        return jsonify(tasksArr), 200
    except Exception:
        exception("[SERVER]-> Ha ocurrido un error")
        return jsonify({'message': 'Ha ocurrido un error'}), 500
    
@app.route('/deltask', methods=['POST'])
@token_required
def del_task(current_user):
    data = request.get_json()
    try:
        tasks = Task.query.filter_by(id = data['id']).first()
        db.session.delete(tasks)
        db.session.commit()
        return jsonify({'message': 'Tarea eliminada'}), 200
    except Exception:
        exception("[SERVER]-> Ha ocurrido un error")
        return jsonify({'message': 'Ha ocurrido un error'}), 500

@app.route('/stopServer', methods=['GET'])
def stopServer():
    os.kill(os.getpid(), signal.SIGINT)
    return jsonify({ "success": True, "message": "Server is shutting down..." })



if __name__ == '__main__':
    with app.app_context(): 
        db.create_all()
        app.run(debug=True,port=8080)
        