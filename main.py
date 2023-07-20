from flask import Flask, request, jsonify, send_file,after_this_request,session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey, func, and_,cast, Date,text,extract
from PIL import Image
import base64
import io
from pytz import timezone
import face_recognition as fr
import json
import numpy as np
import os
import tempfile
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import random
import string
import secrets
from functools import wraps
import logging
from flask_socketio import SocketIO, emit
from flask_cors import CORS, cross_origin
import time
import sys
import threading
import datetime 
import pyotp
import requests




otp_secret = base64.b32encode(secrets.token_bytes(20)).decode()
otp = pyotp.TOTP(otp_secret)


class Config(object):
    SECRET_KEY= 'you-will-never-guess'


approval_thread = threading.Event()
history_thread = threading.Event()
app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
db_path = os.path.join(os.path.dirname(__file__), 'app3.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
thread = None
thread1=None
thread2 = None
thread3 = None
thread4 = None
thread_lock = threading.Lock()
app.config.from_object(Config)
db = SQLAlchemy(app)
message_thread = threading.Event()
thread = None


cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
socketio = SocketIO(app,logger=True, engineio_logger=True,cors_allowed_origins='*')

class User(db.Model):
    __tablename__ = "User"
    username = db.Column(db.String(80),primary_key=True, unique=True)
    name = db.Column(db.String(80))
    email = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(128))
    admin=db.Column(db.Boolean, default=False, server_default="false")
    phonenumber=db.Column(db.String(80), unique=True)
    employees = relationship('Employees',backref="User", lazy=True)
    store = relationship('Store',backref="User", lazy=True)

    @property
    def password(self):
        raise AttributeError('password is not a readable property')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
   
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def validate_email(email):
        if User.query.filter_by(email = email).first() is not None:
            return False
        else:
            return True
   
    @staticmethod
    def validate_user_name(username):
        if User.query.filter_by(username = username).first() is not None:
            return False
        else:
            return True

    @staticmethod
    def validate_phonenumber(phonenumber):
        if User.query.filter_by(phonenumber = phonenumber).first() is not None:
            return False
        else:
            return True

    def serialize_public(self):
        return {
            'name':self.name,            
            'username': self.username,
            'emailaddress': self.email,
            'phonenumber': self.phonenumber, 
            'admin':self.admin 
        }

    def userserialize_public(self):
        return {
            'name':self.name,
            'username': self.username,
            'emailaddress': self.email,
            'phonenumber': self.phonenumber,  
            'admin':self.admin
        }        
            
       

    def __repr__(self):
        return '<User {}>'.format(self.email)  

    def get_groups(self):
        groups = []
        roles = {}
        print(self.groups)
        for group in self.groups:
            roles[group.group.name]=group.role
            groups.append(Group.serialize(group.group))
        return groups,roles

    def has_groups(self):
        if len(self.get_groups()) > 0:
            return True
        return False


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            app.logger.info('token present')
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            app.logger.info('token not present')
            return jsonify({'message' : 'logged out'})
 
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            app.logger.info('getting user data')
            app.logger.info(data)
            current_user = User.query\
                .filter_by(username = data['public_id'])\
                .first()
        except:
            app.logger.info('exception')
            return jsonify({
               'message' : 'logged out'})
        # returns the current logged in users contex to the routes
        app.logger.info('success')
        return  f(current_user, *args, **kwargs)
 
    return decorated



def parse(string):
    d = {'True': True, 'False': False}
    return d.get(string, string)
     
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login Form"""
    if request.method == 'POST':
        try:          
         user = User.query.filter_by(email=request.json['emailaddress']).first()
         if user is not None and user.check_password(request.json['password']):        
                token = jwt.encode({
                    'public_id': user.username,
                }, app.config['SECRET_KEY'])
                app.logger.info('login sucessful')
                return jsonify({'status':True,'token':token.decode('utf-8'),'data':User.userserialize_public(user)})
         else:  
              app.logger.error('email method user name already exists')
              return jsonify({'status':False})
        except:
            app.logger.error('Login function exception triggered')
            return jsonify({'status':False})
    else:
      return jsonify({'status':False})

def generate_key():
    return ''.join(random.choice(string.ascii_letters + string.digits)  for _ in range(50))

@app.route('/register/', methods=['POST'])
def register():
    """Register Form"""
    random_string = generate_key()
    try:
      if request.method == 'POST':
        value_email = User.validate_email(request.json['emailaddress'])
        value_phonenumber = User.validate_phonenumber(request.json['phonenumber'])
        value_user = User.validate_user_name(random_string)
        
        if value_email and value_phonenumber and value_user:
            new_user = User(
                email = request.json['emailaddress'],
                password = request.json['password'],
               username =  random_string,
               name = request.json['name'],
               admin = parse(request.json['admin']),
               phonenumber = request.json['phonenumber']
               )
            db.session.add(new_user)
            db.session.commit()
            app.logger.info('registration success')
            return jsonify({'status':True,'data':User.serialize_public(new_user)})
        else:
          app.logger.error('registration data already exists')
          return jsonify({'status':False})
      else:
        app.logger.error('registration wrong request')
        return jsonify({'status':False})
    except:
      app.logger.error('registration function exception triggered')
      return jsonify({'status':False})

@app.route("/currentuser", methods=['GET'])
@token_required
def Current_user(user):
        app.logger.info('Current user acessed')
        return jsonify({'emailaddress':user.email,'admin':user.admin,'phonenumber':user.phonenumber,'username':user.username,'name':user.name})
   

@app.route('/getOTP', methods=('GET', 'POST'))
def get_otp():
    if request.method == "POST":
        if request.json['phonenumber']:
            user = User.query.filter_by(phonenumber=request.json['phonenumber']).first()
            if user is not None:
              code = otp.now()
              url = f"https://2factor.in/API/V1/56a193e4-ddf3-11ed-addf-0200cd936042/SMS/+91{request.json['phonenumber']}/{code}/OTP1"
              response = requests.request("GET", url)
              text = json.loads(response.text)

              if text['Status'] == 'Success':
                  session['otp_code'] = code
                  print(session.get('otp_code'))

                  app.logger.info('OTP sent successfully')
                  return jsonify({'status':True, "code":code})
              else:
                  app.logger.error('sms not sent')
                  return jsonify({'status':False, "code":''})  
            else:
                app.logger.error('phone verification user exists')      
                return jsonify({'status':False, "code":''})  
        else:
          app.logger.error('no phone number was sent from client')
          return jsonify({'status':False, "code":''})
    else:
      app.logger.error('wrong request send to funcion get_otp')
      return jsonify({'status':False, "code":''})

@app.route('/verifyOTP', methods=['POST'])
def verify_otp():
    if request.method == "POST":
        user = User.query.filter_by(phonenumber=request.json['phonenumber']).first()
        user_id = user.username
        user_isadmin = user.admin

        if request.json['verification-code']:
            code = request.json['verification-code']
            is_valid = otp.verify(code)
            if is_valid:
                token = jwt.encode({
                    'public_id': user.username,
                }, app.config['SECRET_KEY'])
                app.logger.info('otp verified successfully')
                return jsonify({'status' :True,'token' : token.decode('UTF-8'),'data':User.serialize_public(user)})
            else:
                app.logger.error('session otp was not pertinant')
                return jsonify({"status":False})
        else:
            app.logger.error('no verification code sent in request')
            return jsonify({"status":False})
    else:
        app.logger.error('wrong request sent to verify otp')
        return jsonify({"status":False})



class Employees(db.Model):
  __tablename__ = "Employees"
  userId=db.Column(db.String(128),primary_key=True,nullable=False,unique=True)
  imageId = db.Column(db.String(128))  
  firstName = db.Column(db.String(128), nullable=False)
  lastName = db.Column(db.String(128), nullable=False)
  emailId = db.Column(db.String(128), nullable=False)
  phoneNumber = db.Column(db.String(128), nullable=False)
  specialization = db.Column(db.String(128), nullable=False)
  aadharNumber = db.Column(db.String(128), nullable=False)
  address = db.Column(db.String(128), nullable=False)
  experience = db.Column(db.String(128), nullable=False)
  radius = db.Column(db.String(128), nullable=False)
  lat = db.Column(db.String(128), nullable=False)
  longi = db.Column(db.String(128), nullable=False)
  approval = relationship('Approval',backref="Employees", lazy=True)
  history = relationship('History',backref="Employees", lazy=True)
  location = relationship('LiveLocation',backref="Employees", lazy=True)
  attendance = relationship('Attendance',backref="Employees", lazy=True)
  payment = relationship('Payments',backref="Employees", lazy=True)
  shift = relationship('Shift',backref="Employees", lazy=True)
  leave = relationship('Leave',backref="Employees", lazy=True)
  storeid= db.Column(db.String,ForeignKey("Store.storeId"))
  admin = db.Column(db.String,ForeignKey("User.username"))

@token_required
@app.route('/employee/adddata', methods=['POST'])
def employee_adddata():
  if request.method == 'POST':
    try:
      emp = Employees.query.get(request.json['userId'])
      if emp is None:
        obj = Employees(
           userId = request.json['userId'],
          firstName = request.json['firstName'],
          lastName = request.json['lastName'],
          storeid = request.json['storeId'],
          imageId = request.json['imageId'],
          emailId = request.json['emailId'],
          phoneNumber = request.json['phoneNumber'],
          specialization = request.json['specialization'],
          aadharNumber = request.json['aadharNumber'],
          address = request.json['address'],
          experience = request.json['experience'],
          radius = request.json['radius'],
          longi = request.json['longi'],
          lat = request.json['lat'],  
          admin = request.json['admin']    
        )
        db.session.add(obj)
        db.session.commit()
        return jsonify({'status':True})
      else:
        return jsonify({'status':False})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/employee/delete/<string:id>', methods=['GET'])
def employee_deletedata(id):
  if request.method == 'GET':
    try:
      obj = Employees.query.filter_by(userId=id).delete()
      db.session.delete(obj)
      db.session.commit()
      return jsonify({'status':True})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/employee/getdata/<string:id>', methods=['GET'])
def employee_getdata(id):
  if request.method == 'GET':
    try:
      employees= {}  
      employee = Employees.query.filter_by(userId=id).first()
      employees= {'userId': employee.userId,'firstName' : employee.firstName, 'lastName' : employee.lastName,'emailId' : employee.emailId,'phoneNumber' : employee.phoneNumber,'specialization' : employee.specialization,
      'lat' : employee.lat,'longi' : employee.longi,'storeId' : employee.storeid,'imageId' : employee.imageId,'aadharNumber' : employee.aadharNumber,'address' : employee.address,'experience' : employee.experience,'radius' : employee.radius,}
      app.logger.info('successful')
      return jsonify({'status':True,'data':employees})
    except:
      app.logger.info('failed')
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})



@token_required
@app.route('/employeeadmin/getdata/<string:id>', methods=['GET'])
def employeeadmin_getdata(id):
  if request.method == 'GET':
    try:
      all_employees= []  
      employees = Employees.query.filter_by(admin=id).all()
      if len(employees)>0:
        for employee in employees:
          employe= {'userId': employee.userId,'firstName' : employee.firstName, 'lastName' : employee.lastName,'emailId' : employee.emailId,'phoneNumber' : employee.phoneNumber,'specialization' : employee.specialization,
          'lat' : employee.lat,'longi' : employee.longi,'storeId' : employee.storeid,'imageId' : employee.imageId,'aadharNumber' : employee.aadharNumber,'address' : employee.address,'experience' : employee.experience,'radius' : employee.radius,'admin':employee.admin}
          all_employees.append(employe)
          employe={}

      print(all_employees)    
      return jsonify({'status':True,'data':all_employees})
    except:
      app.logger.info('failed')
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})


@token_required
@app.route('/employee/update', methods=['POST'])
def update_employee():
     if request.method == 'POST':
        try:
            employee_to_update = Employees.query.filter_by(userId=request.json['empid']).first()
            if employee_to_update is not None:
              employee_to_update.imageId = str(request.json['imageId'])
              db.session.commit()
              app.logger.info('employee updated sucessfully')
              return jsonify({'status':True})
            else:
              app.logger.info('employee updation failed') 
              return jsonify({'status':False})
        except:
          app.logger.info('employee updation exception triggered')   
          return jsonify({'status':False})
     else:
      app.logger.info('employee updation request error')   
      return jsonify({'status':False})      


class Approval(db.Model):
  __tablename__ = "Approval"
  id = db.Column(db.Integer,primary_key=True)
  empname = db.Column(db.String(128), nullable=False)
  imageid = db.Column(db.String(128), nullable=False)
  empid = db.Column(db.String(128), ForeignKey("Employees.userId"))

@token_required
@app.route('/approval/adddata', methods=['POST'])
def approval_adddata():
  if request.method == 'POST':
    try:
      obj = Approval(
         empid = request.json['empId'],
         empname = request.json['empName'],
         imageid = request.json['imageId'],      
      )
      db.session.add(obj)
      db.session.commit()
      app.logger.info('approval added sucessfully')
      return jsonify({'status':True})
    except:
      app.logger.error('approval addata exception triggered')      
      return jsonify({'status':False})
  else:
    app.logger.error('approval addata wrong request')
    return jsonify({'status':False})

@token_required
@app.route('/approval/delete/<string:id>', methods=['GET'])
def approval_deletedata(id):
  if request.method == 'GET':
    try:
      obj = Approval.query.filter_by(empid=id).delete()
      db.session.commit()
      app.logger.info('approval deleted sucessfully')
      return jsonify({'status':True})
    except:
      app.logger.error('approval delete exception triggered')      
      return jsonify({'status':False})
  else:
    app.logger.error('approval delete wrong request')
    return jsonify({'status':False})

@socketio.on('/approval/stop_thread', namespace="/approval-stop")
def approvals_threads():
        app.logger.info("your thread is stopped approval")
        if approval_thread.is_set():
            global thread
            approval_thread.clear()
            with thread_lock:
              if thread is not None:
                  thread = None
        else:
            app.logger.info("Your socket is not open")


def backgroundapproval_thread(data):
  while approval_thread.is_set():
    try:
      all_approval= []  
      approvals = Approval.query.join(Employees).filter_by(admin=data).all()
      if len(approvals) > 0 :
        for approval in approvals:
          all_approval.append({'empId':approval.empid,'empName':approval.empname,'imageId':approval.imageid})
        app.logger.info(all_approval);
        emit("/approval/getdata",{"data" :all_approval})
      else:
        app.logger.info('no approval');  
        emit("/approval/getdata",{"data" :[]})
    except:
      app.logger.info('exception triggered');
      emit("/approval/getdata",{"data" :[]})
    finally:
      time.sleep(2)
  
   
@socketio.on('/approval/getdata', namespace="/approval-getdata")
def approval_getdata(id):
  app.logger.info('connected approval')
  app.logger.info('received message: ' + str(id))  
  global thread
  with thread_lock:
    app.logger.info('approval is locked')  
    if thread is None:
        approval_thread.set()
        thread3 = socketio.start_background_task( backgroundapproval_thread(id))
  emit("/approval/getdata",{"data" :[]})


@token_required
@app.route('/approval/getdata/<string:approval>', methods=['GET'])
def approval_getdata(approval):
  if request.method == 'GET':
    try:
      all_approval= []  
      approvals = Approval.query.join(Employees).filter_by(admin=approval).all()
      if len(approvals) > 0 :
        for approval in approvals:
          all_approval.append({'empId':approval.empid,'empName':approval.empname,'imageId':approval.imageid})
        app.logger.info(all_approval);
        return jsonify({'status':True,'data':all_approval})
      else:
        return jsonify({'status':False})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})


class History(db.Model):
  __tablename__ = "History"
  id = db.Column(db.Integer,primary_key=True)
  checkin = db.Column(db.String(128))
  randomint = db.Column(db.String(128))
  checkout = db.Column(db.String(128))
  hrspent = db.Column(db.String(128))
  userid = db.Column(db.String(128), ForeignKey("Employees.userId"))

@token_required
@app.route('/history/updatedata', methods=['POST'])
def history_updatedata():
  if request.method == 'POST':
    try:        
      obj = {
         'userid' : request.json['userId'],
         'checkin' : request.json['checkIn'],
         'checkout' : request.json['checkOut'],
         'hrspent' : request.json['hrsSpent']        
      }
      history = History.query.filter_by(randomint=request.json['randomint']).first()
      for key, value in obj.items():
        setattr(history, key, value)

      db.session.commit()
      db.session.flush()
      print(history.checkin)
      print(history.checkin)
      app.logger.info('History, data updated sucessfully')
      return jsonify({'status':True})
    except:
      app.logger.error('hsitory updatedata exception triggered')
      return jsonify({'status':False})
  else:
    app.logger.error('hsitory updatedata wrong request')
    return jsonify({'status':False})

@token_required
@app.route('/history/adddata', methods=['POST'])
def history_adddata():
  if request.method == 'POST':
    try:
      history_id = str(random.randint(0,900))  
      history = History.query.filter_by(randomint=history_id).first()
      if history is None:
        obj = History(
           userid = request.json['userId'],
           checkin = request.json['checkIn'],
           checkout = request.json['checkOut'],
           hrspent = request.json['hrsSpent'],
           randomint = history_id,        
        )
        db.session.add(obj)
        db.session.commit()
        app.logger.info('hsitory adddata successfull')
        return jsonify({'status':True,'data':history_id})
      else:
        app.logger.error('hsitory adddata historyid already available')
        jsonify({'status':False})
    except:
      app.logger.error('hsitory adddata exception triggered')
      return jsonify({'status':False})
  else:
    app.logger.error('hsitory adddata wrong request')
    return jsonify({'status':False})


@socketio.on('/history/stop_thread', namespace="/history-stopthread")
def history_threads():
    app.logger.info("your history thread is stopped")
    if history_thread.is_set():
        app.logger.info("history_thread")
        global thread3
        history_thread.clear()
        with thread_lock:
          if thread3 is not None:
              thread3 = None
    else:
        app.logger.info('Your history thread is not locked')

def backgroundhistory_thread(id):
  while history_thread.is_set():  
    try:
      all_history = []  
      historys = History.query.filter_by(userid=id).all()
      if len(historys) > 0:
        for history in historys:
          all_history.append({'userId':history.userid,'checkIn':history.checkin,'checkOut':history.checkout,'hrsSpent':history.hrspent})
          app.logger.info(all_history)
          emit("/history/getdata",{"data" :all_history})
      else:
        app.logger.info('no history')
        emit("/history/getdata",{"data" :[]})
    except:
      app.logger.info('exception triggered');
      emit("/history/getdata",{"data" :[]})
    finally:
        time.sleep(2)  

    
  

@socketio.on('/history/getdata', namespace="/history-getdata")
def history_getdata(id):
  app.logger.info('connected')
  app.logger.info('received message: ' + str(id))  
  global thread3
  with thread_lock:
    if thread3 is None:
        history_thread.set()
        thread3 = socketio.start_background_task(backgroundhistory_thread(id))
  emit("/history/getdata",{"data" :[]})


@token_required
@app.route('/history/getdata/<string:history>', methods=['GET'])
def history_getdata(history):
    if request.method == 'GET':
        try:
            all_history = []  
            today_date = datetime.datetime.now().date()
            historys = History.query.filter(History.userid == history).all()
            filtered_historys = [h for h in historys if datetime.datetime.strptime(h.checkin, '%Y-%m-%d %H:%M:%S.%f').date() == today_date]

            if len(filtered_historys) > 0:
                for history in filtered_historys:
                    all_history.append({'userId':history.userid,'checkIn':history.checkin,'checkOut':history.checkout,'hrsSpent':history.hrspent})
                    app.logger.info(all_history)
                    print(all_history)
                return jsonify({'status':True,'data':all_history})
            else:
                return jsonify({'status':False})
        except:
            return jsonify({'status':False})
    else:
        return jsonify({'status':False})

@token_required
@app.route('/history/getdataday/', methods=['GET'])
def history_getdataday():
    if request.method == 'GET':
        all_history = []
        userid = request.args.get('userid')
        date_str = request.args.get('time')
        given_date = datetime.datetime.strptime(date_str, '%d/%m/%Y').date()

        print("User ID:", userid)
        print("Date string:", date_str)
        print("Given date:", given_date)

        historys = History.query.filter(History.userid == userid).all()

        print("Historys:", historys)

        filtered_historys = [h for h in historys if datetime.datetime.strptime(h.checkin, '%Y-%m-%d %H:%M:%S.%f').date() == given_date]

        print("Filtered historys:", filtered_historys)

        if len(filtered_historys) > 0:
            for history in filtered_historys:
                all_history.append({'userId': history.userid, 'checkIn': history.checkin, 'checkOut': history.checkout, 'hrsSpent': history.hrspent})
                app.logger.info(all_history)
            return jsonify({'status': True, 'data': all_history})
        else:
            return jsonify({'status': False})
    else:
        return jsonify({'status': False})

@token_required
@app.route('/history/getdataweek/', methods=['GET'])
def history_getdataweek():
    if request.method == 'GET':
        #try:
            all_history = []
            userid = request.args.get('userid')
            start_date_str = request.args.get('start_date')
            end_date_str = request.args.get('end_date')

            if start_date_str == 'select date':
                start_date = datetime.datetime.now().date() - datetime.timedelta(days=7)
            else:
                start_date = datetime.datetime.strptime(start_date_str, '%d/%m/%Y').date()

            if end_date_str == 'select date':
                end_date = datetime.datetime.now().date()
            else:
                end_date = datetime.datetime.strptime(end_date_str, '%d/%m/%Y').date()
            
            historys = History.query.filter(
                and_(
                    History.userid == userid,
                    func.DATE(func.datetime(History.checkin)) >= start_date,
                    func.DATE(func.datetime(History.checkin)) <= end_date
                )
            ).all()

            if len(historys) > 0:
                for history in historys:
                    all_history.append({'userId': history.userid, 'checkIn': history.checkin, 'checkOut': history.checkout, 'hrsSpent': history.hrspent})
                    app.logger.info(all_history)
                return jsonify({'status': True, 'data': all_history})
            else:
                return jsonify({'status': False})
        #except:
        #    return jsonify({'status': False})
    else:
        return jsonify({'status': False})

@token_required
@app.route('/history/getdatamonth/', methods=['GET'])
def history_getdatamonth():
    if request.method == 'GET':
        target_month = datetime.datetime.strptime(request.args.get('month'), '%d/%m/%Y')
        userid = request.args.get('userid')

        all_history = []
        historys = History.query.filter(
            and_(
                History.userid == userid,
                extract('year', History.checkin) == target_month.year,
                extract('month', History.checkin) == target_month.month
            )
        ).all()

        if len(historys) > 0:
            for history in historys:
                all_history.append({'userId': history.userid, 'checkIn': history.checkin, 'checkOut': history.checkout, 'hrsSpent': history.hrspent})
                app.logger.info(all_history)
            return jsonify({'status': True, 'data': all_history})
        else:
            return jsonify({'status': False})
    else:
        return jsonify({'status': False})
    
@token_required
@app.route('/history/delete/<string:id>', methods=['GET'])
def history_deletedata(id):
  if request.method == 'GET':
    try:
      obj = History.query.filter_by(userId=id).delete()
      db.session.delete(obj)
      db.session.commit()
      app.logger.info('hsitory deletedata sucessful')      
      return jsonify({'status':True})
    except:
      app.logger.error('hsitory deletedata exception triggered')
      return jsonify({'status':False})
  else:
    app.logger.error('hsitory deletedata wrong request')
    return jsonify({'status':False})


class Store(db.Model):
  __tablename__ = "Store"
  storeId = db.Column(db.String(128),primary_key=True, nullable=False)
  radius = db.Column(db.String(128), nullable=False)
  storeName = db.Column(db.String(128), nullable=False)
  lat = db.Column(db.String(128), nullable=False)
  longi = db.Column(db.String(128), nullable=False)
  employee = relationship("Employees", backref='Store', lazy=True)
  admin = db.Column(db.String,ForeignKey("User.username"))

@token_required
@app.route('/store/adddata', methods=['POST'])
def Store_adddata():
  if request.method == 'POST':
    try:
      store = Store.query.get(request.json['storeId'])
      if store is None:
        obj = Store(
           storeId = request.json['storeId'],
           radius = request.json['radius'],
           storeName = request.json['storeName'],
           lat = request.json['lat'],
           admin = request.json['admin'],    
           longi = request.json['longi'],          
        )
        db.session.add(obj)
        db.session.commit()
        return jsonify({'status':True})
      else:
        return jsonify({'status':False})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/store/getdata/<string:store>', methods=['GET'])
def Store_getdata(store):
  if request.method == 'GET':
    try:
      all_stores = []  
      stores = Store.query.filter_by(admin=store).all()
      if len(stores)>0:
        for store in stores:
          all_stores.append({'storeId':store.storeId,'radius':store.radius,'storeName':store.storeName,'admin':store.admin,'lat':store.lat,'longi':store.longi})
        print(all_stores)
        return jsonify({'status':True,'data':all_stores})
      else:
        return jsonify({'status':False})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/store/delete/<string:store>', methods=['GET'])
def Store_deletedata(store):
  if request.method == 'GET':
    try:
      obj = Store.query.filter_by(storeId=store).delete()
      db.session.delete(obj)
      db.session.commit()
      return jsonify({'status':True})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})


class Images(db.Model):
    __tablename__ = "Images"
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    img = db.Column(db.LargeBinary)

@token_required
@app.route('/deletefile/<string:name>', methods=['GET'])
def delete_file(name):
  if request.method == 'GET':
    try:  
      obj = Images.query.filter_by(name=name).delete()
      db.session.delete(obj)
      db.session.commit()
      return jsonify({'status':True})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/image/<string:filename>', methods=['GET'])
def download_image(filename):
  if request.method == 'GET':
    try:  
        images = Images.query.filter_by(name=filename).first()
        if not images.img:
            return jsonify({'status':False})

        return send_file(
            io.BytesIO(images.img),
            as_attachment=False,
            mimetype='image/png')
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/img-profile', methods=['POST'])
def upload_profile():
  if request.method == 'POST':
    try:
      file = request.files['file']
      data = file.read()
      newFile = Images(name=file.filename, img=data)
      db.session.add(newFile)
      db.session.commit()
      return jsonify({'status':True,"file_name": file.filename})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})



class Attendance(db.Model):
    __tablename__ = "Attendance"
    id = db.Column(db.Integer,primary_key=True)
    encoding = db.Column(db.String)
    employee_id = db.Column(db.String(128), ForeignKey("Employees.userId"))

@token_required
@app.route('/get_status/<string:name>' ,methods=['GET'])
def image(name):
  if request.method == 'GET':
    try:
      attendances = Attendance.query.filter_by(employee_id=name).all()
      if len(attendances)>0:
        for attendance in attendances:
          if attendance.encoding is not None:
            return jsonify({"Status": True})
        return jsonify({"Status": False})
      else:
        return jsonify({"Status": False})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})


@token_required
@app.route('/img-upload', methods=['POST'])
def upload_image():
  if request.method == 'POST':
    @after_this_request
    def remove_file(response):
      try:
        if tempimage_path is not None:
          os.remove(tempimage_path)
      except Exception as error:
        print("Error removing or closing downloaded file handle", error)
      return response  
    try:
      file = request.files['file']
      data = file.read()
      tempimage_path = os.path.join(os.path.dirname(os.path.abspath("__file__")), file.filename)
      with open(tempimage_path, 'wb') as fp:
         fp.write(data)
      target_img = fr.load_image_file(file.filename)
      target_encoding = fr.face_encodings(target_img)
      if len(target_encoding) > 0:
        target_encoding = json.dumps(list(target_encoding[0]))
        newFile = Attendance(employee_id = request.form['employee_id'] , encoding = target_encoding)
        db.session.add(newFile)
        db.session.commit()
        return jsonify({'status':False,"file_name": file.filename})
      else:
        newFile = Attendance( employee_id = request.form['employee_id'] )
        db.session.add(newFile)
        db.session.commit()
        return jsonify({'status':False,"file_name": ''})    
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/check_attendance', methods=['POST'])
def attendance():
  if request.method == 'POST':
    try:
      matches=[]
      file = request.files['file']
      data = file.read()
      tempimage_path = os.path.join(os.path.dirname(os.path.abspath("__file__")), file.filename)
      with open(tempimage_path, 'wb') as fp:
         fp.write(data)  
      known_image = fr.load_image_file(tempimage_path)
      encoding = fr.face_encodings(known_image)
      if len(encoding)>0:
        attendances = Attendance.query.filter_by(employee_id = request.form['employee_id']).all()
        for attendance in attendances:
          if attendance is not None and encoding is not None:
            known_encodings = np.array(json.loads(attendance.encoding))
            matches.append(fr.compare_faces([known_encodings], encoding[0]))
        for match in matches:
          if match[0] == True:
            return jsonify({"status": True})
          else:  
            return jsonify({"status": False})
      else:
        return jsonify({"status": False})      
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})    

@token_required
@app.route('/delete/<string:name>', methods=['GET'])
def delete_entry(name):
  if request.method == 'GET':
    try:  
      obj = Attendance.query.filter_by(employee_id=name).delete()
      db.session.delete(obj)
      db.session.commit()
      return jsonify({'status':True})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

class LiveLocation(db.Model):
    __tablename__ = "LiveLocation"
    location_key = db.Column(db.String, primary_key=True, unique=True)
    userid = db.Column(db.String(128), ForeignKey("Employees.userId"))
    lat = db.Column(db.String(128))
    longi = db.Column(db.String(128))
    time_created = db.Column(db.DateTime)

    def __init__(self, location_key, userid,lat ,longi,time_created):
        self.location_key = location_key 
        self.longi = longi
        self.userid = userid
        self.lat = lat
        self.time_created = time_created
 
    def serialize(self):
        return {
            'location_key':self.location_key,
            'longi' : self.longi, 
            'userid': self.userid,
            'lat': self.lat,
            'time':self.time_created
          }

@token_required
@app.route('/api/location-add', methods=['POST'])
def add_location():
          json_data = request.get_json(force=True)
          location_key = generate_key()
          location = LiveLocation.query.filter_by(location_key=location_key).first()
          while location:
              location_key = generate_key()
              location_key = LiveLocation.query.filter_by(location_key = location_key).first()
          location = LiveLocation(            
            location_key= location_key, 
            userid = json_data['userid'],
            lat = json_data['lat'],
            longi = json_data['longi'],
            time_created = datetime.datetime.strptime(json_data['time'], "%Y-%m-%d %H:%M:%S.%f"),
            )
          db.session.add(location)
          db.session.commit()
          result = LiveLocation.serialize(location)
          return {"status": 'success', 'data': result}, 200

@token_required
@app.route('/api/location-get', methods=['GET'])
def get_location():
       result = []
       today = datetime.date.today()
       location = LiveLocation.query.filter(LiveLocation.userid == request.args.get('userid'),db.func.date(LiveLocation.time_created) == today).order_by(LiveLocation.time_created.desc()).all()#.filter_by(time_created = date.today())
       if location:
         for loc in location:
           result.append(LiveLocation.serialize(loc))
         print(result)
         return {"status": 'success', 'data': result}, 200
       else:
         return {"status": "Leave Not Found"}, 404

class Payments(db.Model):
    __tablename__ = "Payments"
    payments_key = db.Column(db.String, primary_key=True, unique=True)
    userid = db.Column(db.String(128), ForeignKey("Employees.userId"))
    notes = db.Column(db.String(128))
    category = db.Column(db.String(128))
    type_of_note = db.Column(db.String(128))
    ammount = db.Column(db.Integer)
    time_created = db.Column(db.DateTime)

    def __init__(self, payments_key, userid,time,notes ,ammount,type_of_note, category):
        self.payments_key = payments_key 
        self.notes = notes
        self.userid = userid
        self.time_created = time
        self.ammount = ammount
        self.type_of_note = type_of_note
        self.category = category
 
    def serialize(self):
        return {
            'payments_key':self.payments_key,
            'ammount' : self.ammount, 
            'userid': self.userid,
            'notes': self.notes,
            'category' : self.category,
            'type_of_note' : self.type_of_note,
            'time': self.time_created.strftime("%m/%d/%Y"),
          }



@token_required
@app.route('/api/payments-add', methods=['POST'])
def add_payments():
          json_data = request.get_json(force=True)
          payments_key = generate_key()
          print(json_data['time'])
          print(datetime.datetime.strptime(json_data['time'], '%d/%m/%Y'))
          print(type(datetime.datetime.strptime(json_data['time'], '%d/%m/%Y')))
          payments = Payments.query.filter_by(payments_key=payments_key).first()
          while payments:
              payments_key = generate_key()
              payments_key = Payments.query.filter_by(payments_key = payments_key).first()
          payments = Payments(            
            payments_key= payments_key, 
            userid = json_data['userid'],
            notes = json_data['notes'],  
            category = json_data['category'],
            time = datetime.datetime.strptime(json_data['time'], '%d/%m/%Y'),
            ammount = json_data['ammount'],
            type_of_note =  json_data['type_of_note']
            )
          db.session.add(payments)
          db.session.commit()
          return {"status": True}, 200

@token_required
@app.route('/api/payments-get', methods=['GET'])
def get_payments():
       result = []
       date_string = request.args.get('range')
       date = datetime.datetime.strptime(date_string, "%B, %Y")
      
       year = date.year
       month = date.month
       start_date = datetime.datetime(year, month, 1, tzinfo = datetime.timezone.utc)
       end_date = start_date.replace(month=start_date.month % 12 + 1, day=1) - datetime.timedelta(days=1)

       payments = Payments.query.filter_by(userid=request.args.get('userid'), category=request.args.get('category')).\
            filter(Payments.time_created >= start_date, Payments.time_created <= end_date).order_by(Payments.time_created.desc()).all()
       if payments:
         total_amount = sum(payment.ammount for payment in payments)
         for payment in payments:
           result.append(Payments.serialize(payment))
         return {"status": 'success', 'data': result, 'total':total_amount}, 200
       else:
         return {"status": "Leave Not Found"}, 404

@token_required
@app.route('/api/ledgerdata-get', methods=['GET'])
def get_ledgerdata():
       result = []

       date_string = request.args.get('range')
       print(date_string)
       if(date_string == 'All'):
           print('ALL')
           payments = Payments.query.filter_by(userid=request.args.get('userid')).order_by(Payments.time_created.desc()).all()           
       else:
           date = datetime.datetime.strptime(date_string, "%B, %Y")
           year = date.year
           month = date.month
           start_date = datetime.datetime(year, month, 1, tzinfo = datetime.timezone.utc)
           end_date = start_date.replace(month=start_date.month % 12 + 1, day=1) - datetime.timedelta(days=1)       
           payments = Payments.query.filter_by(userid=request.args.get('userid')).\
                filter(Payments.time_created >= start_date, Payments.time_created <= end_date).order_by(Payments.time_created.desc()).all()
       if payments:
         total_credit = sum(payment.ammount for payment in payments if payment.type_of_note == 'Credit')
         total_debit = sum(payment.ammount for payment in payments if payment.type_of_note == 'Debit')
         Balance = total_debit - total_credit 
         for payment in payments:
           result.append(Payments.serialize(payment))
         return {"status": 'success', 'data': result, 'total_credit':total_credit,'total_debit':total_debit,'Balance':Balance}, 200
       else:
         return {"status": False}, 404



@token_required
@app.route('/api/payments_delete/<string:payments_key>', methods=['GET'])
def delete_payments(payments_key):
  if request.method == 'GET':
    try:  
      payments = Payments.query.filter_by(payments_key=payments_key).first()
      if payments:
        db.session.delete(payments)
        db.session.commit()
        return jsonify({'status':True})
      else:
        return jsonify({'status':False})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})


class Shift(db.Model):
    __tablename__ = "Shift"  
    userid = db.Column(db.String(), ForeignKey("Employees.userId")) 
    day = db.Column(db.DateTime, primary_key=True, unique=True) 
    shift_type = db.Column(db.String(80))
    
    def __init__(self ,userid, day, shift_type):
        self.userid = userid
        self.day = day
        self.shift_type = shift_type

    def serialize(self):
        return {
            'type_of_shift': self.shift_type,
            'date': self.day.strftime("%d/%m/%Y"),
            'userid': self.userid,
          }


@token_required
@app.route('/api/Shift-add', methods=['PUT'])
def add_shift():  
    json_data = request.get_json(force=True)
    shift = Shift.query.filter_by(day=datetime.datetime.strptime(json_data['date'], '%Y-%m-%d %H:%M:%S.%f')).first()
    if shift:
        if (shift.shift_type != json_data['type_of_shift']):
           shift.shift_type = json_data['type_of_shift']
        db.session.commit()
        return {"status": True}, 200
    else:
        shift = Shift(            
            shift_type = json_data['type_of_shift'],
            day =  datetime.datetime.strptime(json_data['date'], '%Y-%m-%d %H:%M:%S.%f'),
            userid = json_data['userid'],)
        db.session.add(shift)
        db.session.commit()
        return {"status": True}, 200

@token_required
@app.route('/api/LeaveShift-add', methods=['PUT'])
def add_Leaveshift():      
  json_data = request.get_json(force=True)
  start_date = datetime.datetime.strptime(json_data['startdate'], '%d/%m/%Y')
  end_date = datetime.datetime.strptime(json_data['enddate'], '%d/%m/%Y')
  try: 
     for n in range(int((end_date - start_date).days) + 1):
        date = start_date + datetime.timedelta(n)
        shift = Shift.query.filter_by(day=date).first()
        if shift:
          if (shift.shift_type != 'Leave'):
           shift.shift_type = 'Leave'
           db.session.commit() 
        else:
            shift = Shift(            
              shift_type = 'Leave',
              day =  date,
              userid = json_data['userid'],)
            db.session.add(shift)
            db.session.commit()
     return {"status": True}, 200
  except:
    return {"status": False}, 404



@token_required
@app.route('/api/shift-get', methods=['GET'])
def get_shift():
       morningshift = []
       nightshift = []
       leaveshift = []
       shifts = Shift.query.filter_by(userid = request.args.get('userid')).all()
       if shifts:
         for shift in shifts:
          if shift.shift_type == 'Morning Shift':
            morningshift.append(Shift.serialize(shift))
          elif shift.shift_type == 'Night Shift':
            nightshift.append(Shift.serialize(shift))
          elif shift.shift_type == 'Leave':
            leaveshift.append(Shift.serialize(shift))
         return {"status": True, 'nightshift' : nightshift, 'morningshift' : morningshift,  'leaveshift': leaveshift}, 200
       else:
         return {"status": False}, 404

class Leave(db.Model):
    __tablename__ = "Leave"
    leave_key = db.Column(db.String, primary_key=True, unique=True)    
    userid = db.Column(db.String(), ForeignKey("Employees.userId"))
    reason = db.Column(db.String(80))
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime) 
    duration = db.Column(db.String(80))

 
    def __init__(self, leave_key,userid,duration,start_date,end_date,reason): 
        self.leave_key = leave_key
        self.userid = userid
        self.reason = reason
        self.duration = duration
        self.start_date = start_date
        self.end_date = end_date

 
    def serialize(self):
        
        return {
            'leave_key' : self.leave_key,
            'userid': self.userid,
            'reason': self.reason,
            'duration': self.duration,
            'start_date': self.start_date.strftime("%d/%m/%Y"),
            'end_date': self.end_date.strftime("%d/%m/%Y")
          }


@token_required
@app.route('/api/leave-add', methods=['POST'])
def add_leave():
          json_data = request.get_json(force=True)
          leave_key = generate_key()
          leave = Leave.query.filter_by(leave_key=leave_key).first()
          while leave:
              leave_key = generate_key()
              leave_key = Leave.query.filter_by(leave_key = leave_key).first()
          leave = Leave(            
            leave_key= leave_key, 
            userid = json_data['userid'],
            reason = json_data['reason'],
            end_date =  datetime.datetime.strptime(json_data['end_date'], '%Y-%m-%d %H:%M:%S.%f'),
            start_date =  datetime.datetime.strptime(json_data['start_date'], '%Y-%m-%d %H:%M:%S.%f'),
            duration = json_data['duration'])
          
          db.session.add(leave)
          db.session.commit()
          result = Leave.serialize(leave)
          return {"status": True, 'data': result}, 200


@token_required
@app.route('/api/leave-get', methods=['GET'])
def get_leave():
       result = []
       leaves = Leave.query.join(Employees).filter(Employees.admin == request.args.get('userid')).all()
       if leaves:
         for leave in leaves:
            dummy = {}
            dummy = Leave.serialize(leave)
            dummy['empid'] = leave.Employees.userId
            dummy['name'] = leave.Employees.firstName + " " + leave.Employees.lastName
            dummy['phonenumber'] = leave.Employees.phoneNumber
            result.append(dummy)
         print(result)   
         return {"status": True, 'data': result}, 200
       else:
         return {"status": False}, 404



@token_required
@app.route('/api/leave-delete/', methods=['DELETE'])
def leave_delete():
        leave = Leave.query.filter_by(leave_key=request.args.get('leave_key')).first()
        if leave:
              db.session.delete(leave)
              db.session.commit()
              return {"status": True}, 200
        else:
              return {"status": False}, 404

class Group_Member_Association(db.Model):
    __tablename__ = "association_table"
    group_id = db.Column(db.ForeignKey("groups.group_key", ondelete="CASCADE"), primary_key=True)
    user_id = db.Column(db.ForeignKey("User.username", ondelete="CASCADE"), primary_key=True)
    role = db.Column(db.String(50),default='நிர்வாகம்')
    group = db.relationship("Group", backref=db.backref("members",cascade="save-update, merge, ""delete, delete-orphan",passive_deletes=True))
    user = db.relationship("User", backref=db.backref("groups",cascade="save-update, merge, ""delete, delete-orphan",passive_deletes=True))

      


user_assigned_to_subtask_table = db.Table(
    'user_assigned_to_subtask',
    db.Model.metadata,
    db.Column('user_id', db.Integer(),
              db.ForeignKey('User.username', ondelete='CASCADE'),
              primary_key=True
              ),
    db.Column('subtask_id', db.String(),
              db.ForeignKey('subtasks.subtask_key', ondelete='CASCADE'),
              primary_key=True
              ),
)

class Message(db.Model):
    __tablename__ = 'message'
    message = db.Column(db.String(), nullable=False)
    sender = db.Column(db.String(), nullable=False)
    time_created = db.Column(db.DateTime(
        timezone=False), server_default=db.func.now())
    subtask_key = db.Column(db.String(),
                         db.ForeignKey('subtasks.subtask_key', ondelete="CASCADE"))
    message_key = db.Column(db.String(), unique=True,primary_key=True)

    def __init__(self, message, sender, subtask_key, message_key):
        self.message = message
        self.subtask_key = subtask_key
        self.sender = sender
        self.message_key = message_key

    def serialize(self):
        return {
            'subtaskKey': self.subtask_key,
            'message': self.message,
            'sender': self.sender,
            'messageKey': self.message_key,
            'time_created': self.time_created.isoformat(),
        }


class Task(db.Model):
    __tablename__ = 'tasks'

    title = db.Column(db.String(), nullable=False)
    completed = db.Column(db.Boolean(), default=False)
    priority = db.Column(db.Integer(), default=1)
    time_created = db.Column(db.DateTime(
        timezone=False), server_default=db.func.now())
    time_updated = db.Column(db.DateTime(
        timezone=False), onupdate=db.func.now())
    group_key = db.Column(db.String(),
                         db.ForeignKey('groups.group_key', ondelete="CASCADE"))
    task_key = db.Column(db.String(), unique=True,primary_key=True)

    def __init__(self, title, group_key, task_key):
        self.title = title
        self.task_key = task_key
        self.group_key = group_key

    def serialize(self):
        if self.time_updated is None:
            time_updated = self.time_created.isoformat()
        else:
            time_updated = self.time_updated.isoformat()
        return {
            'title': self.title,
            'group_key': self.group_key,
            'priority': self.priority,
            'completed': self.completed,
            'task_key': self.task_key,
            'time_created': self.time_created.isoformat(),
            'time_updated': time_updated,
        }


class SubTask(db.Model):
    __tablename__ = 'subtasks'
    task_key = db.Column(db.String(),
                        db.ForeignKey('tasks.task_key', ondelete="CASCADE"))
    subtask_key = db.Column(db.String(), unique=True, primary_key=True)
    title = db.Column(db.String(), nullable=False)
    completed = db.Column(db.Boolean(), default=False)
    note = db.Column(db.String(), default="")
    due_date = db.Column(db.DateTime(timezone=False))
    priority = db.Column(db.Integer(), default=1)
    reminders = db.Column(db.String())
    time_created = db.Column(db.DateTime(
        timezone=False), server_default=db.func.now())
    time_updated = db.Column(db.DateTime(
        timezone=False), onupdate=db.func.now())
    assigned_to_user = db.relationship("User",
                                       secondary=user_assigned_to_subtask_table,
                                       backref="subtask")

    def __init__(self, title, task_key, subtask_key):
        self.title = title
        self.task_key = task_key
        self.subtask_key = subtask_key

    def serialize(self):
        if self.time_updated is None:
            time_updated = self.time_created.isoformat()
        else:
            time_updated = self.time_updated.isoformat()
        return {
            'task_key': self.task_key,
            'subtask_key': self.subtask_key,
            'title': self.title,
            'completed': self.completed,
            'note': self.note,
            'priority': self.priority,
            'due_date': datetime.date.today().isoformat() if self.due_date is None else self.due_date.isoformat(),
            'reminders': self.reminders,
            'time_created': self.time_created.isoformat(),
            'time_updated': time_updated,
            'message_count': self.get_messagae_count(), 
        }

    def get_messagae_count(self):
      messages = Message.query.filter_by(subtask_key=self.subtask_key).count()
      if messages:
        return int(messages)



    def get_users_assigned_to(self):
        assigned_to = []
        for user in self.assigned_to_user:
            assigned_to.append(User.serialize_public(user))
        return assigned_to


class Group(db.Model):
    __tablename__ = 'groups'

    name = db.Column(db.String())
    group_key = db.Column(db.String(), unique=True, primary_key=True)
    is_public = db.Column(db.Boolean(), default=True)
    time_created = db.Column(db.DateTime(
        timezone=False), server_default=db.func.now())
    time_updated = db.Column(db.DateTime(
        timezone=False), onupdate=db.func.now())


    def __init__(self, name, group_key, is_public):
        self.name = name
        self.group_key = group_key
        self.is_public = is_public

    def serialize(self):
        if self.time_updated is None:
            time_updated = self.time_created.isoformat()
        else:
            time_updated = self.time_updated.isoformat()
        return {
            'name': self.name,
            'members': self.get_members(),
            'group_key': self.group_key,
            'is_public': self.is_public,
            'time_created': self.time_created.isoformat(),
            'time_updated': time_updated,
        }

    def get_members(self):
        members = []
        for member in self.members:
            role = member.role
            print(member.user)
            data=User.serialize_public(member.user)
            data['role']=role
            members.append(data)
        return members

    def is_empty(self):
        if len(self.get_members()) == 0:
            return True
        return False    


@app.route('/api/group', methods=['GET'])  
@token_required   # Generate new api key
def get_groups(user):
     result = []
     roles={}
     user = User.query.filter_by(username=request.args.get('username')).first()
     if user:
        result,roles = user.get_groups()
        return {"status": 'success', 'data': result,'roles':roles}, 200
     else:
      return {"status": "No api key!"}, 401   

@app.route('/api/group-add', methods=['POST'])
@token_required
def add_groups(user):
       json_data = request.get_json(force=True)
       user = User.query.filter_by(username=json_data['username']).first()
       if user:
          group_key = generate_key()
          group = Group.query.filter_by(group_key=group_key).first()
          while group:
              group_key = generate_key()
              group = Group.query.filter_by(group_key=group_key).first()

          group = Group(name=json_data['name'],
                        group_key=group_key,
                        is_public=json_data['is_public'])
          role=Group_Member_Association(group=group,role=json_data['role'])
          with db.session.no_autoflush:
            user.groups.append(role)  
          db.session.add(group)
          db.session.commit()
          result = Group.serialize(group)
          return {"status": 'success', 'data': result}, 200
       else:
          return {"status": "No user with that api key"}, 404
 
@app.route('/api/group-update', methods=['PATCH'])
@token_required
def group_update(user):
      json_data = request.get_json(force=True)
      group = Group.query.filter_by(group_key=json_data['group_key']).first()
      if group:
        if (group.name != json_data['name']):
           group.name = json_data['name']
        if (group.is_public != json_data['is_public']):
           group.is_public = json_data['is_public']
        db.session.commit()
        return {"status": 'success'}, 200
      else:
        return {"status": "No Group with that group key"}, 404

@app.route('/api/group-delete', methods=['DELETE'])
@token_required
def group_delete(user):
      group = Group.query.filter_by(group_key = request.args.get('group_key')).first()
      if group:
         db.session.delete(group)
         db.session.commit()
         return {"status": 'success'}, 200
      else:
         return {"status": 'Group Not Found'}, 404


@app.route('/api/groupmember-add', methods=['POST'])
@token_required
def add_groupmember(user):
        json_data = request.get_json(force=True)
        group = Group.query.filter_by(group_key = json_data['groupKey']).first()
        if group:
            if group.is_public:
                user = User.query.filter_by(username=json_data['username']).first()
                if user:
                  for m in group.members:
                            if user.username == m.user.username:
                                result = User.serialize_public(user) 
                                return {"status": "User is already added",'data': result}, 200
                  role=Group_Member_Association(user=user,role=json_data['role'])
                  with db.session.no_autoflush:
                    group.members.append(role)
                  db.session.commit()
                  return {"status": 'success'}, 200
                else:
                   return { "status": 'No user found by that username'}, 404
            else:
                return {"status": 'Group is not public'}, 403
        else:
          return {"status": "No Group Found with that group key"}, 404

@app.route('/api/groupmember-get', methods=['GET'])
@token_required
def get_groupmember(user):
       result = []
       group = Group.query.filter_by(group_key=request.args.get('groupKey')).first()
       if group:
         result = group.get_members()
         return {"status": 'success', 'data': result}, 200
       else:
         return {"status": "Group Not Found"}, 404

@app.route('/api/groupmember-update', methods=['PATCH'])
@token_required
def update_groupmember(user):
    json_data = request.get_json(force=True)
    username = json_data['username']
    group = Group.query.filter_by(group_key=json_data['groupKey']).first()
    if group:
      for m in group.members:
        if m.user.username == username:
            with db.session.no_autoflush:
              m.role= json_data['role']
              db.session.commit() 
              return {"status": 'success'}, 200
      return {"status": "Member Not Found in Group"}, 404
    else:
      return {"status": "Group Not Found"}, 405    


@app.route('/api/groupmember-delete', methods=['DELETE'])
@token_required
def delete_groupmember(user):
    username = request.args.get('username')
    group = Group.query.filter_by(group_key=request.args.get('groupKey')).first()
    if group:
      for m in group.members:
        if m.user.username == username:
            with db.session.no_autoflush:
              group.members.remove(m)
            db.session.commit()  
            if group.is_empty():
              db.session.delete(group)
              db.session.commit()
            return {"status": 'success'}, 200
      return {"status": "Member Not Found in Group"}, 404
    else:
      return {"status": "Group Not Found"}, 405    


@app.route('/api/search', methods=['POST'])
@token_required
def search(user):
   result = []
   json_data = request.get_json(force=True)
   print(json_data['search_term'])
   filtered_list = User.query.filter(
            User.email.startswith(json_data['search_term'])).all()
   for user in filtered_list:
       result.append(User.serialize_public(user))
   return {"status": 'success', 'data': result}, 200

@app.route('/api/assignedtouserhURL-get', methods=['GET'])
@token_required
def assignedtouserhURL_get(user):
       result = []
       subtask = SubTask.query.filter_by(subtask_key=request.args.get('subtask_key')).first()
       if subtask:
            result = subtask.get_users_assigned_to()
            return {"status": 'success', 'data': result}, 200
       else:
            return {"status": "Subtask Not Found"}, 404

@app.route('/api/assignedtouserhURL-add', methods=['POST'])
@token_required
def assignedtouserhURL_add(user):
            json_data = request.get_json(force=True)
            username = json_data['username']
            subtask = SubTask.query.filter_by(subtask_key=json_data['subtask_key']).first()
            if subtask:
                user = User.query.filter_by(
                    username=username).first()
                if user:
                    # Check each member the subtask is assigned to, if a match with the provided username, then remove assignment
                    for m in subtask.assigned_to_user:
                        if user.username == m.username:
                            return {"status": "User is already assigned to Task"}, 201
                    subtask.assigned_to_user.append(user)
                    db.session.commit()
                    return {"status": 'success'}, 201
                else:
                    return {"status": "No user found by that username"}, 404
            else:
                return {"status": "Subtask Not Found"}, 404





@app.route('/api/assignedtouserhURL-delete', methods=['DELETE'])
@token_required
def assignedtouserhURL_delete(user):
      username = request.args.get('username')
      subtask = SubTask.query.filter_by(subtask_key=request.args.get('subtask_key')).first()
      if subtask:
        for m in subtask.assigned_to_user:
          if m.username == username:
            subtask.assigned_to_user.remove(m)
            db.session.commit()
            return {"status": 'success'}, 200
        return {"status": "Subtask not assigned to User"}, 404
      else:
        return {"status": "Subtask Not Found"}, 404    

@app.route('/api/tasks-add', methods=['POST'])
@token_required
def tasks_add(user):
    json_data = request.get_json(force=True)
    task_key = generate_key()
    task = Task.query.filter_by(task_key=task_key).first()
    while task:
          task_key = generate_key()
          task = Task.query.filter_by(task_key=task_key).first()

    task = Task(
            title=json_data['title'],
            group_key=json_data['group_key'],
            task_key=task_key,
            )
    db.session.add(task)
    db.session.commit()
    return {"status": 'success'}, 201

    # List Task //Change to List GROUP TASK, NO NESTED FOR LOOP
@app.route('/api/tasks-get', methods=['GET'])
@token_required
def tasks_get(user):
   result = []
   tasks = Task.query.filter_by(group_key=request.args.get('group_key')).all()
   for task in tasks:
       result.append(Task.serialize(task))
   return {"status": 'success', 'data': result}, 200

    # Update Task
@app.route('/api/tasks-update', methods=['PATCH'])
@token_required
def tasks_update(user):
        json_data = request.get_json(force=True)
        task = Task.query.filter_by(task_key=json_data['task_key']).first()
        if task:
          if (task.completed != json_data['completed']):
              task.completed = json_data['completed']
          if(task.priority != json_data['priority']):
              task.priority = json_data['priority']                        
          db.session.commit()
          result = Task.serialize(task)
          return {"status": 'success', 'data': result}, 200
        else:
          return {"status": "No Task with that task key"}, 404

    # Delete Task
@app.route('/api/tasks-delete', methods=['DELETE'])
@token_required
def tasks_delete(user):
        task = Task.query.filter_by(task_key=request.args.get('task_key')).first()
        if task:
              db.session.delete(task)
              db.session.commit()
              return {"status": 'success'}, 200
        else:
              return {"status": 'No Task found with that task key'}, 404


@app.route('/api/subtasks-add', methods=['POST'])
@token_required
def sub_task_add(user):
            json_data = request.get_json(force=True)
            subtask_key = generate_key()
            subtask = SubTask.query.filter_by(subtask_key=subtask_key).first()
            while subtask:
               subtask_key = generate_key()
               subtask = SubTask.query.filter_by(subtask_key=subtask_key).first()
            subtask = SubTask(
                    title=json_data['title'],
                    task_key=json_data['taskKey'],
                    subtask_key=subtask_key,)
            db.session.add(subtask)
            db.session.commit()
            return {"status": 'success'}, 201

    # List Subtasks
@app.route('/api/subtasks-get', methods=['GET'])
@token_required
def sub_task_get (user):
         result = []
         subtasks = SubTask.query.filter_by(task_key=request.args.get('taskKey')).all()
         for subtask in subtasks:
           result.append(SubTask.serialize(subtask))
         return {"status": 'success', 'data': result}, 200

@app.route('/api/subtasks-update', methods=['PATCH'])
@token_required
def sub_task_update (user):
   json_data = request.get_json(force=True)
   subtask = SubTask.query.filter_by(subtask_key=json_data['subtask_key']).first()
   if subtask:
       if (subtask.note != json_data['note']):
          subtask.note = json_data['note']
       if (subtask.completed != json_data['completed']):
          subtask.completed = json_data['completed']
       if (subtask.priority != json_data['priority']):
          subtask.priority = json_data['priority']   
       if (subtask.due_date != datetime.datetime.fromisoformat(json_data['due_date'])):
          subtask.due_date = datetime.datetime.fromisoformat(json_data['due_date'])
       db.session.commit()
       return {"status": 'success'}, 200
   else:
      return { "status": 'No Subtask found with that subtask key'}, 404


@app.route('/api/subtasks-delete', methods=['DELETE'])
@token_required
def sub_task_delete (user):
    subtask = SubTask.query.filter_by(subtask_key=request.args.get('subtask_key')).first()
    if subtask:
      db.session.delete(subtask)
      db.session.commit()
      return {"status": 'success'}, 200
    else:
      return { "status": 'No Subtask found with that subtask key'}, 404

@app.route('/api/message_send', methods=['POST'])
@token_required
def send_message(user):
    json_data = request.get_json(force=True)
    message_key = generate_key()
    message = Message.query.filter_by(message_key=message_key).first()
    while message:
          message_key = generate_key()
          message = Message.query.filter_by(message_key=message_key).first()

    message = Message(
             message = json_data['message'],
            sender = json_data['sender'],
            subtask_key = json_data['subtaskKey'],
            message_key = message_key,
            )
    db.session.add(message)
    db.session.commit()
    return {"status": 'success'}, 201

 

@app.route('/api/message-get', methods=['GET'])
@token_required
def message_get (user):
         result = []
         messages = Message.query.filter_by(subtask_key=request.args.get('subtask_key')).order_by(Message.time_created.desc()).all()
         if messages:
            for message in messages:
               result.append(Message.serialize(message))
            return {"status": 'success', 'data': result}, 200
         else:
           return {"status": 'failure', 'data': result}, 200
 
@socketio.on('/message/stop_thread', namespace="/message-disconnect")
def message_threads():
    print("your message thread is stopped")
    if message_thread.is_set():
        print("message_thread")
        global thread4
        message_thread.clear()
        with thread_lock:
          if thread4 is not None:
              thread4 = None
    else:
        print('Your message thread is not locked')

def backgroundhistory_thread(id):
  while message_thread.is_set():  
    try:
         result = []
         messages = Message.query.filter_by(subtask_key=id).order_by(Message.time_created.desc()).all()
         if messages:
            for message in messages:
               result.append(Message.serialize(message))
            print(result)   
            emit("/message/get",{"data" :result})
         else:
            print('no messages')
            emit("/message/get",{"data" :[]})
    except:
      print('exception triggered');
      emit("/message/get",{"data" :[]})
    finally:
        time.sleep(3)  

    
  

@socketio.on('/message/get', namespace="/message-get")
def message_getdata(id):
  print('connected')
  print('received message: ' + str(id))  
  global thread4
  with thread_lock:
    if thread4 is None:
        message_thread.set()
        thread4 = socketio.start_background_task(backgroundhistory_thread(id))
  emit("/message/get",{"data" :[]})



if __name__ == '__main__':
    with app.app_context():
      db.create_all()    
    app.run()