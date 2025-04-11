# using flask to display site
from flask import Flask, render_template, redirect, url_for, request, session, flash
#interfacing with mysql
# hashlib for hashing password - keep all stored passwords hashed and secure when in database
import bcrypt
# regex to validate emails
import re
#
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.sql import text
#2fa
import time, datetime
import pyotp
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets

from io import BytesIO
import qrcode
from flask_mail import Mail, Message
import creds
# Creating a Flask instance
app = Flask(__name__)
# Add the databases
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://root:{creds.sql_pwd}@localhost/main"
app.config['SECRET_KEY'] = creds.server_secret_key

# Create engine
engine = create_engine(f"mysql+pymysql://root:{creds.sql_pwd}@localhost/main")

# Initiating email service
app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = "noreply.kellettprogramming@gmail.com"
app.config['MAIL_DEFAULT_SENDER'] = "noreply.kellettprogramming@gmail.com"
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_PASSWORD'] = creds.mail_pwd

mail=Mail(app)


# general functions
def execute_sql(query : str, param={}):
    with engine.connect() as con:
        print(param)
        result = con.execute(text(query), parameters=param)
        con.commit()
    return result

def generate_2fa_secret():
    key=pyotp.random_base32().encode()
    return key

def verify_2fa_code(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
    
def generate_email_otp():
    code = str(secrets.randbelow(10**6)).zfill(6)
    expires_at = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat()
    return code, expires_at

def send_2fa_email(address, code):
    html = render_template('2fa_email_template.html', code=code)

    msg = Message(subject="Your Kellett Programming Verification Code",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[address],
                  html=html)
    with app.open_resource('static/email_temp.gif') as fp:
        msg.attach('email_temp.gif',
                   'image/gif',
                   fp.read(),
                   headers={'Content-ID':'<yippee>'})
    try:
        mail.send(msg)
        return True
    # error handling
    except Exception as e:
        print(f"WARNING | Error sending email to {address}:\nError: {e}")
        return False

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods = ["POST", "GET"])
def login():
    print(request.method)
    if request.method != "POST":
        return render_template("login.html") # initial login state
    else:
        # retrieve form inputs
        email = request.form["email"]
        password = request.form["password"].encode()
        
        # validate email format
        # regex syntax ^ and $ denote start and end of string, in order to filter out attempted sql injection attacks
        if not re.search(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email):
            flash("Invalid email format", "error")
            return redirect(url_for("login"))
        
        # get user
        result = execute_sql("SELECT * FROM users WHERE user_email=:email;", {"email":email})
        user = result.fetchone()  # fetchone finds the first occurance in the result, then returns a named tuple. works similar to class/objects.
        
        # return error if user is not found
        if not user:
            flash("Invalid email or password","error")
            return redirect(url_for("login"))
        
        # authenticate password
        if not(bcrypt.checkpw(password, user.pwd_hash)):
            flash("Invalid email or password", "error")
            return redirect(url_for("login"))
        
        # if all checks passed, create session information
        
        session['uid'] = user.uid                                                                       # general user information.
        session['email'] = email                                                                        #
        
        session['last_action'] = "login"                                                                # record information of what the last action the user did
        match user.two_factor_auth_type:
            case None:
                redirect(url_for("/"))
            case "totp":
                secret = 222222
                if not "DECRYPTED" in str(secret)[-9:]:
                    flash("Secret key was not decrypted properly", "error")
                    return redirect(url_for("login"))
                
                session['2fa_secret'] = secret
                session['2fa_required'] = True                                                                  # saves whether if user needs to do a 2fa or not.
                session['2fa_type'] = user.two_factor_auth_type
                
                session['2fa_expiry'] = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat()         # set timeout/expiry of 2fa secret
                return redirect(url_for("verify"))
            case "email_2fa":
                pass


@app.route("/signup", methods = ["POST", "GET"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"].encode()
        name = request.form["username"]
        if request.form["password"]!=request.form["retype_password"]:
            flash("Not the same password", "error")
            return redirect(url_for("signup"))

        # validate email format. 
        if re.search(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email)==None:
            flash("Invalid email format", "error")
            return redirect(url_for("signup"))
        
        #check if there is already an existing email.
        if execute_sql(f"SELECT * FROM users WHERE user_email=:email;",{'email':email}).fetchone()!=None:
            flash("Email already in use.", "error")
            return redirect(url_for("signup"))
        
        # generating a new salt
        salt = bcrypt.gensalt()
        # hashing the password using bcrypt    
        hashed_password = bcrypt.hashpw(password, salt)
                                                                                                         # general user information. UID should only be generated when the account is confirmed to be created.
        session['email'] = email                                                                        #
        session['last_action'] = "signup" 
        session['2fa_required'] = False 
        session['hashed_password']=hashed_password
        session['name']=name
        if "2fa_type" in request.form: # if user wants to have 2fa:
            session['2fa_required'] = True # saves in session whether if user needs to do a 2fa or not.
            session['attempts'] = 0 # count attempts made to enter 2fa code
            if request.form["2fa_type"]=="totp":
                # creating secret key for user
                # generate key using password
                kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=os.urandom(16),
                iterations=480000,
                backend = default_backend() # potentially dangerous?
                )
                secret=generate_2fa_secret() 
                session['2fa_secret'] = secret # gets deleted later
                # encrypt 2fa secret here in order to keep the password always within signup page and isnt stored afterwards.
                key=base64.urlsafe_b64encode(kdf.derive(password)) # key derived using password
                session['encrypted_2fa_secret'] = Fernet(key).encrypt(secret) # encrypted using key generated above
                session['2fa_expiry'] = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat() # set expiry
                session['2fa_type'] = "totp"

            elif request.form["2fa_type"]=="email":
                # generate 6 digit code
                session['2fa_code'], session['2fa_expiry']=generate_email_otp() 
                session['2fa_type'] = "email"
                if not send_2fa_email(session['email'], session['2fa_code']): # if code unsuccessfully sent:
                    # render site
                    flash("Email unable to be sent due to unexpected error.", "error")

            else:
                flash("Invalid 2fa type", "error")
                return redirect(url_for("signup"))

        
        if session['2fa_required'] == False:
            return redirect(url_for("")) #return to home page
        else:
            return redirect(url_for("setup_2fa"))
        
    else:
        print('a')
        return render_template("signup.html")

@app.route("/setup_2fa", methods=["GET","POST"])
def setup_2fa( ):
    #check for expiry
    if datetime.datetime.now().isoformat()<session['2fa_expiry'] and session['attempts']<=5:
        if request.method=="GET":
            if session['2fa_type']=="totp":
                #setup totp
                secret=session['2fa_secret']
                totp = pyotp.TOTP(secret)
                
                memory = BytesIO()
                provisioning_uri = totp.provisioning_uri(name = session['email'], issuer_name="Kellett Programming Week")
                img = qrcode.make(provisioning_uri)
                img.save(memory)
                memory.seek(0)
                base64_img = "data:image/png;base64," + \
                            base64.b64encode(memory.getvalue()).decode('ascii')
                return render_template("otp_setup.html", code=secret.decode(), qr = base64_img, type="totp", signup=True)

            elif session['2fa_type']=="email":
                #setup 2fa via email
                return render_template("otp_setup.html", email=session['email'], type="email")
            


        elif request.method=="POST":
            # assemble the code back together
            code = request.form['otp1']+request.form['otp2']+request.form['otp3']+request.form['otp4']+request.form['otp5']+request.form['otp6']
            if session['2fa_type']=="totp":
                secret=session['2fa_secret']
                totp = pyotp.TOTP(secret)
                if not code == totp.now():
                    session['attempts']+=1
                    return redirect(url_for("setup_2fa"))
                execute_sql("""INSERT INTO users(uid, username, user_email, pwd_hash, secret, two_factor_auth_type, user_score) 
                            VALUES(:uid, :username, :email, :pwd_hash, :secret, :2fa, :userscore)""", {
                            'uid': 0 ,  # Should this be auto-incremented instead? TODO
                            'username': session['name'],
                            'email': session['email'],
                            'pwd_hash': session['hashed_password'],                                                                                                                                                                                                                                                                                                                                              
                            'secret': session['encrypted_2fa_secret'],
                            '2fa':"totp",
                            'userscore': 0})
                # 2fa passed
                #stop saving 2fa related details
                session.pop('2fa_secret')
                session.pop('totp')
                session.pop('2fa_required')
                session.pop('2fa_type')

            elif session['2fa_type']=="email":
                print(code,session['2fa_code'])
                if not code == session['2fa_code']:
                    session['attempts']+=1
                    return redirect(url_for("setup_2fa"))
                execute_sql("""INSERT INTO users(uid, username, user_email, pwd_hash, two_factor_auth_type, user_score) 
                            VALUES(:uid, :username, :email, :pwd_hash, :2fa, :userscore)""", {
                            'uid': 0 ,  # Should this be auto-incremented instead? TODO fix
                            'username': session['name'],
                            'email': session['email'],
                            'pwd_hash': session['hashed_password'],
                            '2fa':"email",
                            'userscore': 0})
                # code is correct
                session.pop('2fa_code')
                session.pop('2fa_required')
                session.pop('2fa_type')
    else:
        # timeout, return to signup
        flash("Exceeded 2fa verification period or exceeded 2fa attempts", "message")
        return redirect(url_for("signup"))
@app.route("/verify", methods=["GET","POST"])
def verify():
    print("hhhh")
    # checks if there is a valid session
    if 'uid' not in session:
        return redirect(url_for("/" if not ('last_action' in session) else (session['last_action'])))       #redirect to home page or login or signup depending on last action
    
    # check for 2fa expiry
    if datetime.datetime.now() >= session["2fa_expiry"]:
        session.clear() # clear session cookies - prevents clutter and logs out user.
        flash(f"Session expired, please {"login" if not (session["last_action"]=="signup") else ("sign up")} again", "error")
        return redirect(url_for("login" if not (session["last_action"]=="signup") else ("signup")))
    
    if not "2fa_required" in session:
        return redirect(url_for(session['last_action']))
    

    # 2fa process begins after all checks are paassed
    if request.method == "POST": # user has entered 2fa code
        if not pyotp.totp.verify(request.form['code']): # returns boolean
            return redirect(url_for("verify_2fa"))     # incorrect code
        else:
            session['authenticated'] = True
            session.pop('2fa_required', None)
    
    else:
        if session['2fa_type']=='totp':
            # parse in the secret into the html so that it can be scanned
            pass
        else:
            pass
    print(session)
    return render_template("twofactorauth.html", auth_type=("pytotp" if session['2fa_type'] == 'totp' else "two_factor_auth"))                                                                                #TODO 2FA SITE TEMPLATE

@app.route("/debug")
def debug():
    return render_template("2fa_email_template.html", code="069420")
if __name__ == "__main__":
    app.run(debug=True)