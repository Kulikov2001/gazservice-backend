from flask import Flask, jsonify, request, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from marshmallow import ValidationError
from models import db, User, Work
from schemas import UserSchema, WorkSchema
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_session import Session
from datetime import datetime
import bcrypt
import os
import json

app = Flask(__name__)
CORS(app)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db.init_app(app)
# Configure the JWT
app.config['JWT_SECRET_KEY'] = 'myjwtverysecret'  # Change this to a random secret key
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit
jwt = JWTManager(app)
#bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
# API эндпоинты для Users

with app.app_context():
    db.create_all()  # Create database tables if they don't exist

@app.route('/users', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        user_schema = UserSchema()
        user = user_schema.load(data)
        db.session.add(User(**user))
        db.session.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

@app.route('/logout', methods=['POST'])
def logout():
    # Clear the JWT token from the session
    session.pop('jwt_token', None)
    return jsonify({"msg": "Logged out successfully"}), 200

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    if user is None:
        return jsonify({'error': 'User not found'}), 404
    user_schema = UserSchema()
    return jsonify(user_schema.dump(user))

@app.route('/users/<int:user_id>', methods=['PATCH'])
def update_user(user_id):
    try:
        data = request.get_json()
        user_schema = UserSchema()
        user = User.query.get(user_id)
        if user is None:
            return jsonify({'error': 'User not found'}), 404
        user_schema.load(data, instance=user)
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user is None:
        return jsonify({'error': 'User not found'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing username or password'}), 400

    username = data['username']
    password = data['password'].encode('utf-8')

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(password, user.password):
        access_token = create_access_token(identity=username)
        session['jwt_token'] = access_token
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if 'username' not in data or 'password' not in data or 'role' not in data:
        return jsonify({'error': 'Missing username, password, or role'}), 400

    username = data['username']
    password = data['password'].encode('utf-8')  # Encode password to bytes
    role = 'worker'

    # Check if the username already exists
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'error': 'Username already exists'}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

    # Create a new user
    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'success': True})
# API эндпоинты для Works

@app.route('/works', methods=['POST'])
def create_work():
    print("Request files:", request.files)
    print("Request form:", request.form)
    if 'photo' not in request.files:
        return jsonify({'error': 'No photo part'}), 400
    file = request.files['photo']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    timestamp = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
    original_filename = file.filename
    filename, file_extension = os.path.splitext(original_filename)
    new_filename = f"{filename}--{timestamp}{file_extension}"
    
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
    try:
        data = request.form.get('data')
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        work_data = json.loads(data)
        work_data['photo'] = new_filename
        work_schema = WorkSchema()
        work = work_schema.load(work_data)
        db.session.add(Work(**work))
        db.session.commit()
        return jsonify({'message': 'Work created successfully'}), 201
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

@app.route('/works', methods=['GET'])
#@jwt_required(locations=['cookies'])
def get_works():
    #curr_user = get_jwt_identity()
   # if current_user is None:
        # If no token is provided or the token is invalid, return a custom response
    #    return jsonify({"msg": "Please provide a valid JWT token"}), 401
    works = Work.query.all()
    work_schema = WorkSchema(many=True)
    return jsonify(work_schema.dump(works))

@app.route('/works/<int:work_id>', methods=['GET'])
def get_work(work_id):
    work = Work.query.get(work_id)
    if work is None:
        return jsonify({'error': 'Work not found'}), 404
    work_schema = WorkSchema()
    return jsonify(work_schema.dump(work))

@app.route('/works/<int:work_id>', methods=['PATCH'])
def update_work(work_id):
    try:
        data = request.get_json()
        work_schema = WorkSchema()
        work = Work.query.get(work_id)
        if work is None:
            return jsonify({'error': 'Work not found'}), 404
        work_schema.load(data, instance=work)
        db.session.commit()
        return jsonify({'message': 'Work updated successfully'})
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

@app.route('/works/<int:work_id>', methods=['DELETE'])
def delete_work(work_id):
    work = Work.query.get(work_id)
    if work is None:
        return jsonify({'error': 'Work not found'}), 404
    db.session.delete(work)
    db.session.commit()
    return jsonify({'message': 'Work deleted successfully'})

@app.route('/uploads/<filename>', methods=['GET'])
def get_photo(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True, host='192.168.70.218', port=5000) # ssl_context=('cert.pem', 'key.pem'),