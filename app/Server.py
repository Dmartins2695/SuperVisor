import base64
import datetime
import os
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_jwt_extended import (
    JWTManager
)
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256 as sha256

app = Flask(__name__)
api = Api(app)
parser = reqparse.RequestParser()
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Lolada123@localhost/LPI'
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = '%tY24$iKao@£Po&'
# IMAGE_FOLDER = os.path.join('static', 'serverImages')
# app.config['UPLOAD_FOLDER'] = IMAGE_FOLDER
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
jwt = JWTManager(app)


def check_for_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message': 'Missing Token'}), 403
        try:
            data: jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': ' Invalid token'}), 403
        return func(*args, **kwargs)

    return wrapped

    # cria todas as tabelas


@app.before_first_request
def create_tables():
    db.create_all()


# @jwt.token_in_blacklist_loader
# def check_if_token_in_blacklist(decrypted_token):
#     jti = decrypted_token['jti']
#     return RevokedTokenModel.is_jti_blacklisted(jti)


# DATABASE SECTION


class RoomModel(db.Model):
    __tablename__ = 'roomsCreated'

    def __init__(self, roomName, code, owner):
        self.roomName = roomName
        self.code = code
        self.owner = owner

    roomName = db.Column(db.String(120), nullable=False)
    code = db.Column(db.String(150), primary_key=True, unique=True, nullable=False)
    owner = db.Column(db.String(120), nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_code(cls, code):
        return cls.query.filter_by(code=code).first()

    @classmethod
    def find_owner_Rooms(cls, owner):
        return cls.query.filter_by(owner=owner)

    # elimina todos os utilizadores
    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}


class StudentModel(db.Model):
    __tablename__ = 'students'

    def __init__(self, username, email, password, joinedRoom, newImages, status, timeStamp, disable, disabletimeStampo,
                 enabletimeStampo, enable):
        self.username = username
        self.email = email
        self.password = password
        self.joinedRoom = joinedRoom
        self.newImages = newImages
        self.status = status
        self.timeStamp = timeStamp
        self.disable = disable
        self.enable = enable
        self.disabletimeStampo = disabletimeStampo
        self.enabletimeStampo = enabletimeStampo

    username = db.Column(db.String(120), primary_key=True, unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    joinedRoom = db.Column(db.String(120), nullable=False)
    newImages = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Integer, nullable=False)
    timeStamp = db.Column(db.String(120))
    disabletimeStampo = db.Column(db.String(120))
    enabletimeStampo = db.Column(db.String(120))
    disable = db.Column(db.Integer, nullable=False)
    enable = db.Column(db.Integer, nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_studentsRoom(cls, joinedRoom):
        return cls.query.filter_by(joinedRoom=joinedRoom).all()

    # verifica se ja existe algum utilizador com esse email

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

        # verifica se ja existe algum utilizador com esse username

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    # para verificar hash no login
    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}


class ImageModel(db.Model):
    __tablename__ = 'images'

    def __init__(self, username, image, timeStamp, roomCode):
        self.username = username
        self.image = image
        self.timeStamp = timeStamp
        self.roomCode = roomCode

    image = db.Column(db.String(120), primary_key=True, unique=True, nullable=False)
    username = db.Column(db.String(120), nullable=False)
    timeStamp = db.Column(db.String(120), nullable=False)
    roomCode = db.Column(db.String(120), nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    # verifica se ja existe algum utilizador com esse email

    @classmethod
    def find_by_image(cls, image):
        return cls.query.filter_by(image=image).first()

    @classmethod
    def find_allImages(cls, username):
        return cls.query.filter(cls.username == username)

    # verifica se ja existe algum utilizador com esse username
    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    # elimina todos os utilizadores
    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}


class UserModel(db.Model):
    __tablename__ = 'users'

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    # id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), primary_key=True, unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    # verifica se ja existe algum utilizador com esse email
    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    # verifica se ja existe algum utilizador com esse username
    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    # para verificar hash no login
    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}


# Web app side
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = request.form.get("user")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        client = UserModel(username=user, email=email, password=UserModel.generate_hash(password))

        if client.find_by_email(email):
            flash('Este email já foi registrado, tente um novo!', 'danger')
            return render_template('register.html')

        elif client.find_by_username(user):
            flash('User já existe, tente um novo!', 'danger')
            return render_template('register.html')

        elif password != confirm:
            flash('Palavra passe errada, tente novamente!', 'danger')
            return render_template('register.html')

        else:
            client.save_to_db()
            flash('Registro efetuado com sucesso!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/showStudentImages/<roomName>/<roomCode>/<studentName>', methods=["GET", "POST"])
def showStudentImages(roomName, roomCode, studentName):
    if request.method == "GET":
        student = StudentModel.find_by_username(studentName)
        if student:
            student.newImages = 0
            student.save_to_db()
            allImages = ImageModel.find_allImages(studentName)
            return render_template('showStudentImages.html', roomName=roomName, roomCode=roomCode,
                                   studentName=studentName,
                                   allImages=allImages, student=student)
        else:
            return redirect(url_for('room', roomName=roomName, roomCode=roomCode))


@app.route('/listRooms', methods=["GET", "POST"])
def listRooms():
    user = session['user']
    ownedRooms = RoomModel.find_owner_Rooms(user)
    return render_template('listRooms.html', ownedRooms=ownedRooms)


@app.route('/room/<roomName>/<roomCode>', methods=["GET", "POST"])
def room(roomName, roomCode):
    allStudents = StudentModel.find_studentsRoom(roomCode)
    return render_template('room.html', roomName=roomName, roomCode=roomCode, allStudents=allStudents)


@app.route('/createRoom', methods=["GET", "POST"])
def createRoom():
    if request.method == "POST":
        rname = request.form.get("roomname")
        code = rname + datetime.now().strftime("%d%m%Y%H%M%S")
        user = session['user']
        room = RoomModel(rname, code, user)
        try:
            room.save_to_db()
            flash('Sala criada com successo!', 'success')
            return redirect(url_for('room', roomName=rname, roomCode=code))
        except:
            flash('Sala já existe!', 'danger')
            return render_template("createRoom.html")
    else:
        return render_template("createRoom.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("user")
        password = request.form.get("password")
        if UserModel.find_by_username(user) is None:
            flash('User ou password errada, tente novamente!', 'danger')
            return render_template('login.html')
        else:
            client = UserModel.find_by_username(user)
            if UserModel.verify_hash(password, client.password):
                session["user"] = user
                # token = jwt._create_access_token({
                #     'user': user,
                #     'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60)
                # },
                # app.config['SECRET_KEY'])
                # session['token']=token
                flash('Login efetuado com successo!', 'success')
                return redirect(url_for('user'))
    else:
        if "user" in session:
            redirect(url_for('user'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop("user", None)
    return redirect(url_for('login'))


@app.route('/user')
# @check_for_token
def user():
    name = session['user']
    return render_template('user.html', messages=name)

    # IMAGE PROCESSING SeCTION


class studentLogin(Resource):
    def post(self):
        parser_upload = parser.copy()
        parser_upload.add_argument('StudentUser', help='code cannot be blank', required=False)
        parser_upload.add_argument('StudentPassword', help='code cannot be blank', required=False)
        data = parser_upload.parse_args()
        user = data['StudentUser']
        password = data['StudentPassword']

        client = StudentModel.find_by_username(user)
        if StudentModel.verify_hash(password, client.password):
            session['Studentuser'] = user
            return {'code': 'sucess'}
        else:
            return {'code': 'wrong_credentials'}


class studentRegister(Resource):
    def post(self):
        parser_upload = parser.copy()
        parser_upload.add_argument('StudentUser', help='code cannot be blank', required=False)
        parser_upload.add_argument('StudentPassword', help='code cannot be blank', required=False)
        parser_upload.add_argument('StudentEmail', help='code cannot be blank', required=False)
        data = parser_upload.parse_args()
        username = data['StudentUser']
        password = data['StudentPassword']
        email = data['StudentEmail']
        student = StudentModel(username=username, email=email, password=StudentModel.generate_hash(password),
                               joinedRoom='none', newImages=0, status=0, timeStamp=None, disable=0,
                               disabletimeStampo=None, enabletimeStampo=None, enable=0)
        student.save_to_db()
        return 200


class receiveCode(Resource):
    def post(self):
        parser_upload = parser.copy()
        parser_upload.add_argument('roomCode', help='code cannot be blank', required=False)
        parser_upload.add_argument('studentName', help='code cannot be blank', required=False)
        data = parser_upload.parse_args()
        code = data['roomCode']
        studentName = data['studentName']
        try:
            room = RoomModel.find_by_code(code)
            if code == room.code:
                student = StudentModel.find_by_username(studentName)
                student.joinedRoom = room.code
                student.status = 1
                student.save_to_db()
                return {'code': 'sucess'}
        except:
            return {
                'code': 'error',
                'message': 'room not found'
            }


class receiveImage(Resource):
    def post(self):
        path = "C:\\Users\danie\OneDrive\Documentos\GitHub\LPI\\app\static\serverImages"
        dbImagepath = '/serverImages'
        parser_upload = parser.copy()
        parser_upload.add_argument('image', help='Image cannot be blank', required=False)
        parser_upload.add_argument('studentName', help='code cannot be blank', required=False)
        parser_upload.add_argument('timestamp', help='code cannot be blank', required=False)
        parser_upload.add_argument('roomCode', help='code cannot be blank', required=False)
        data = parser_upload.parse_args()
        image = data['image']
        studentName = data['studentName']
        timestamp = data['timestamp']
        roomCode = data['roomCode']
        student = StudentModel.find_by_username(studentName)
        bytes = base64.b64decode(image)
        imagepath = path + "\\" + student.username + timestamp + '.jpg'
        try:
            if not os.path.isdir(path):
                os.mkdir(path)
            with open(imagepath, "wb") as img:
                img.write(bytes)
            imagepath = dbImagepath + '/' + student.username + timestamp + '.jpg'
            imgToDb = ImageModel(username=student.username, image=imagepath, timeStamp=timestamp, roomCode=roomCode)
            student.newImages += 1
            student.save_to_db()
            imgToDb.save_to_db()
            return 200
        except:
            return


class receiveLeave(Resource):
    def post(self):
        parser_upload = parser.copy()
        parser_upload.add_argument('logout', help='Image cannot be blank', required=False)
        parser_upload.add_argument('studentName', help='code cannot be blank', required=False)
        parser_upload.add_argument('timestamp', help='code cannot be blank', required=False)
        data = parser_upload.parse_args()

        logout = data['logout']
        timestamp = data['timestamp']
        studentName = data['studentName']
        student = StudentModel.find_by_username(studentName)
        student.status = logout
        student.timeStamp = timestamp
        student.save_to_db()


class receiveDisable(Resource):
    def post(self):
        parser_upload = parser.copy()
        parser_upload.add_argument('disable', help='Image cannot be blank', required=False)
        parser_upload.add_argument('studentName', help='code cannot be blank', required=False)
        parser_upload.add_argument('timestamp', help='code cannot be blank', required=False)
        data = parser_upload.parse_args()

        disable = data['disable']
        timestamp = data['timestamp']
        studentName = data['studentName']
        student = StudentModel.find_by_username(studentName)
        student.disable = disable
        student.disabletimeStampo = timestamp
        student.save_to_db()


class receiveEnable(Resource):
    def post(self):
        parser_upload = parser.copy()
        parser_upload.add_argument('enable', help='Image cannot be blank', required=False)
        parser_upload.add_argument('studentName', help='code cannot be blank', required=False)
        parser_upload.add_argument('timestamp', help='code cannot be blank', required=False)
        data = parser_upload.parse_args()

        enable = data['enable']
        timestamp = data['timestamp']
        studentName = data['studentName']
        student = StudentModel.find_by_username(studentName)
        student.enable = enable
        student.enabletimeStampo = timestamp
        student.save_to_db()


api.add_resource(receiveImage, '/receiveImage', endpoint="receiveImage")
api.add_resource(receiveDisable, '/receiveDisable', endpoint="receiveDisable")
api.add_resource(receiveEnable, '/receiveEnable', endpoint="receiveEnable")
api.add_resource(receiveLeave, '/receiveLeave', endpoint="receiveLeave")
api.add_resource(receiveCode, '/receiveCode', endpoint="receiveCode")
api.add_resource(studentLogin, '/studentLogin', endpoint="studentLogin")
api.add_resource(studentRegister, '/studentRegister', endpoint="studentRegister")

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True, host="192.168.1.81", port="5000")
