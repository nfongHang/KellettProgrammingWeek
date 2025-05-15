# using flask to display site
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_wtf.csrf import CSRFProtect
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
import hashlib
import hmac
from io import BytesIO
import qrcode
from flask_mail import Mail, Message
import creds
import uuid
from authlib.integrations.flask_client import OAuth
#single sign on
import workos

# Creating a Flask instance
app = Flask(__name__)
# Add the databases
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://root:{creds.sql_pwd}@localhost/main"
app.config['SECRET_KEY'] = creds.server_secret_key
csrf = CSRFProtect(app)

# SSO
oauth = OAuth(app)
# defining the different allowed sso types
oauth.register(
    name='github',
    client_id=creds.github_client_id,
    client_secret=creds.github_client_secret,
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    allow_signup=True,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)


# Create engine
engine = create_engine(f"mysql+pymysql://root:{creds.sql_pwd}@localhost/main")
# Initiating email service
app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = creds.email
app.config['MAIL_DEFAULT_SENDER'] = creds.email
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


def checkSessionExpired(expiry_time):
    if datetime.datetime.now().isoformat()>expiry_time:
        return True
    return False

def check_valid_session(session):
    # checking if valid session right now:
    verified=False
    if 'verified' in session:
        # run test
        verified = True

        # if this user has suddenly gotten online again after 1 hour of inactivity:
        if datetime.datetime.now()>datetime.datetime.fromisoformat(session["last_active"])+datetime.timedelta(hours=1):
            #regenerating current hashed UA and IP
            current_hashed_ua = hmac.new(key = app.config['SECRET_KEY'].encode(), # use sha256 to hash the user agent and ip using app secret as a key
                                    msg=request.headers.get('User-Agent')[:256].encode(), 
                                    digestmod=hashlib.sha256).hexdigest() #use sha256 to hash, and convert to hex
            current_hashed_ip = hmac.new(key = app.config['SECRET_KEY'].encode(), # use sha256 to hash the user agent and ip using app secret as a key
                                    msg=request.remote_addr[:45].encode(), 
                                    digestmod=hashlib.sha256).hexdigest() #use sha256 to hash, and convert to hex
            
            # TODO: MAYBE MAKE THE IP AND UA HASH INTO ONE BLOB?

            if not(current_hashed_ip == session["ip_hash"]) and not(current_hashed_ua == session["user_agent_hash"]):
                #log out user
                session.clear()
                flash("You have been logged out: Session expired / Invalid session. Please login again.", "error")
                return verified


        if checkSessionExpired(session['expires_at']):
            #log out user
            session.clear()
            flash("You have been logged out: Session expired / Invalid session. Please login again.", "error")
            return verified
    #update session last active time
        session["last_active"]=datetime.datetime.now().isoformat()
    return verified

@app.route("/error/<error_id>", methods = ["GET"])
def error(error_id):
    return render_template("error.html", error = error_id)

@app.route("/", methods = ["POST","GET"])
def index():
    #handle top right signup/login OR account button
    if request.method=="POST":
        if "login_or_out" in request.form:
            if not "verified" in session:
                # signin
                return redirect(url_for("signup"))
            #logging out
            session.clear()
            flash("Sucessfully logged out.","message")
        elif "account" in request.form and "verified" in session:
            return redirect(url_for("account", uid=session["uid"]))
    return render_template("index.html", verified=check_valid_session(session))


@app.route("/account", methods = ["POST","GET"])
def redirect_account():
    if 'uid' in session:
        return redirect(url_for("account", uid=session['uid']))
    else:
        return redirect(url_for("signup"))
    
@app.route("/account/<uid>", methods = ["POST","GET"])
def account(uid):
    uid=uid.replace("%20"," ")
    #check for case of username entered instead
    #convert to uid
    if len(uid)!=36 or execute_sql("SELECT username FROM users WHERE uid=:uid",{"uid":uid}).fetchone()==None:
        #try and find uid based on username
        uid=execute_sql("SELECT uid FROM users WHERE username=:username",{"username":uid}).fetchone()[0]
    if uid==None:
        return redirect(url_for("error"),error_id=404)
    # attempt to fetch user profile picture
    image=execute_sql("SELECT images FROM user_to_profile_pictures WHERE uid=:uid", {'uid':uid}).fetchone()
    if image==None:
        pass # TODO - SETS IMAGE TO DEFAULT ONE
    else:
        image = "data:image/png;base64," + base64.b64encode(image).decode('utf-8') # encodes bytes into image that can be displayed
    name=execute_sql("SELECT username FROM users WHERE uid=:uid",{"uid":uid}).fetchone()[0]

    #basic button logic
    if request.method=="POST":
        if "login_or_out" in request.form:
            if not "verified" in session:
                # signin
                return redirect(url_for("signup"))
            #logging out
            session.clear()
            flash("Sucessfully logged out.","message")
        elif "account" in request.form and "verified" in session:
            return redirect(url_for("account", uid=session["uid"]))
        # check if this is the user's own account


    return render_template("account.html", verified=check_valid_session(session), uid=uid, image=image, acc_name=name)

@app.route("/login", methods = ["POST", "GET"])
def login():
    if 'verified' in session:
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_template("login.html") # initial login state
    elif request.method == "POST":
        if "login_or_out" in request.form:
            return redirect(url_for("signup"))
        
        # manage single sign on
        if "github_sso" in request.form:
            session.clear()
            session["sso"] = True
            session["sso_type"] = "github"
            return github_login()
        
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
        session.clear()
        session['uid'] = user.uid                                                                       # general user information.
        session['email'] = email                                                                        #
        session['last_action'] = "login"                                                                # record information of what the last action the user did
        match user.two_factor_auth_type:
            case None: # invalid two factor authentication
                flash("User error: Unrecognized authentication method")
                redirect(url_for("/"))

            case "totp":
                session['2fa_required'] = True # saves in session whether if user needs to do a 2fa or not.
                session['attempts'] = 0 # count attempts made to enter 2fa code
                if user.two_factor_auth_type=="totp":
                    # creating secret key for user
                    # generate key using password
                    kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=user.secret_salt,
                    iterations=480000,
                    backend = default_backend() # potentially dangerous?
                    )
                    
                    session['encrypted_2fa_secret'] = user.secret # gets deleted later
                    # encrypt 2fa secret here in order to keep the password always within signup page and isnt stored afterwards.
                    key=base64.urlsafe_b64encode(kdf.derive(password)) # key derived using password
                    session['2fa_secret'] = Fernet(key).decrypt(user.secret) # encrypted using key generated above
                    session['2fa_expiry'] = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat() # set expiry
                    session['2fa_type'] = "totp"
            case "email":
                # generate 6 digit code
                session['attempts'] = 0 
                session['2fa_code'], session['2fa_expiry']=generate_email_otp() 
                session['2fa_type'] = "email"
                if not send_2fa_email(session['email'], session['2fa_code']): # if code unsuccessfully sent:
                    # render site
                    flash("Email unable to be sent due to unexpected error.", "error")
        return redirect(url_for("authenticate"))

def github_login():
    github = oauth.create_client('github')
    redirect_uri = "http://127.0.0.1:5000/authenticate"
    session["sso_type"]="github"
    return github.authorize_redirect(redirect_uri)

def github_authorize(request):
    """ Creates profile dict and returns it from github SSO """
    token = oauth.github.authorize_access_token()
    print(token.get('scope'))
    resp = oauth.github.get('user', token=token)
    resp.raise_for_status()
    profile = resp.json()
    resp = oauth.github.get('user/emails', token=token)
    resp.raise_for_status()
    email = resp.json()
    return profile, email

@app.route("/signup", methods = ["POST", "GET"])
def signup():
    if 'verified' in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        if "github_sso" in request.form:
            session.clear()
            session["sso"] = True
            session["sso_type"] = "github"
            return github_login()
        if "login_or_out" in request.form:
            return redirect(url_for("login"))


        email = request.form["email"]
        password = request.form["password"]
        name = request.form["username"]
        if request.form["password"]!=request.form["retype_password"]:
            flash("Passwords entered are not the same.", "error")
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
        hashed_password = bcrypt.hashpw(password.encode(), salt)
                                                                                                         # general user information. UID should only be generated when the account is confirmed to be created.
        session.clear()
        session['email'] = email
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
                user_salt=os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=user_salt,
                    iterations=480000,
                    backend = default_backend() # potentially dangerous?
                    )
                secret=generate_2fa_secret() 
                session['2fa_secret'] = secret # gets deleted later
                # encrypt 2fa secret here in order to keep the password always within signup page and isnt stored afterwards.
                key=base64.urlsafe_b64encode(kdf.derive(password.encode())) # key derived using password
                session['encrypted_2fa_secret'] = Fernet(key).encrypt(secret) # encrypted using key generated above
                session['2fa_expiry'] = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat() # set expiry
                session['2fa_type'] = "totp"
                session['secret_salt'] = user_salt

            elif request.form["2fa_type"]=="email":
                # generate 6 digit code
                session['2fa_code'], session['2fa_expiry']=generate_email_otp() 
                session['2fa_type'] = "email"
                if not send_2fa_email(session['email'], session['2fa_code']): # if code unsuccessfully sent:
                    # render site
                    flash("Email unable to be sent due to unexpected error.", "error")

            else:
                flash("Invalid 2fa type selected.", "error")
                return redirect(url_for("signup"))
        
        if session['2fa_required'] == False:
            flash("2fa Method is required.","error")
            return redirect(url_for("signup")) #return to home page
        else:
            return redirect(url_for("authenticate"))
        
    else:
        return render_template("signup.html")

def login_procedure(uid, name):
    # delete all user credidentials
        session.clear()
        session.permanent=True # make session permament session - creates persistent cookie
        session.permanent_session_lifetime=datetime.timedelta(days=7) # set session to expire after 7 days and auto log out the user.
        # setup logged in session information
        current_ua = request.headers.get('User-Agent')[:256] # limit length of user agent in order to prevent DOS attack by passing in abnormally long UA 
        current_ip = request.remote_addr[:45] # 45 bits in order to ensure compatability with ipv6
        hashed_ua = hmac.new(key = app.config['SECRET_KEY'].encode(), # use sha256 to hash the user agent and ip using app secret as a key
                                msg=current_ua.encode(), 
                                digestmod=hashlib.sha256).hexdigest() #use sha256 to hash, and convert to hex
        hashed_ip = hmac.new(key = app.config['SECRET_KEY'].encode(), # use sha256 to hash the user agent and ip using app secret as a key
                                msg=current_ip.encode(), 
                                digestmod=hashlib.sha256).hexdigest() #use sha256 to hash, and convert to hex
        session.update({
            'uid' : uid, # user uid
            'last_active' : datetime.datetime.now().isoformat(), # save the last active information
            'verified' : True, # flag in order to highlight that the user is logged in. This should be safe because the cookie is signed and cannot be easily modified
            # get the user agent from https headers -- includes information about browser, device etc. store securely by hashing.
            'user_agent_hash' : hashed_ua,
            # get user ip from https headers. store securely by hashing
            'ip_hash' : hashed_ip,
            'expires_at' : (datetime.datetime.now() + datetime.timedelta(days=14)).isoformat(), # set session expiry date to be after 7 days
            'name' : name
        })
        print("update ok")
        # return to the home site
        return redirect(url_for("index"))

@app.route("/authenticate", methods=["GET","POST"])
def authenticate():
    #manage sso
    verified=False
    if 'sso' in session:
        # TODO implement test for which type of sso
        sso_type=session["sso_type"]
        match sso_type:
            case "github":
                profile, email = github_authorize(request)
                email=email[0]
        # check if email exists in database
        if user_details:=execute_sql("SELECT * FROM users WHERE user_email=:email",{"email":email['email']}).fetchone():
            #check if SSO information already exists. If not, add it.
            user_details=user_details._mapping
            if user_details[sso_type]==None:
                execute_sql(f"UPDATE users SET {sso_type}=True WHERE user_email=:email", {"email":email['email']})
            #login user
            uid=user_details.uid
            name=user_details.username
            # 2fa passed
            verified=True
        else:
            uid=str(uuid.uuid4())
            name=profile['login']
            execute_sql(f"""INSERT INTO users(uid, username, user_email, user_score, {sso_type}) 
                        VALUES(:uid, :username, :email, :pwd_hash, :secret, :2fa, :userscore, :sso)""", {
                        'uid': uid,
                        'username': name,
                        'email': email["email"],
                        'userscore': 0,
                        'sso':True
                        })
            verified=True

    if 'verified' in session or verified:
        return login_procedure(uid,name)
    #check for expiry
    if datetime.datetime.now().isoformat()>session['2fa_expiry'] or session['attempts']>5:
        # timeout, return to signup
        print(session)
        flash("Exceeded 2fa verification period or exceeded 2fa attempts.", "error")
        return redirect(url_for("signup"))
    
    if request.method=="GET":
        if session['2fa_type']=="totp":
            #setup totp
            secret=session['2fa_secret']
            totp = pyotp.TOTP(secret)

            if session['last_action']=='signup': # if signing up:
                memory = BytesIO()
                provisioning_uri = totp.provisioning_uri(name = session['email'], issuer_name="Kellett Programming Week")
                img = qrcode.make(provisioning_uri)
                img.save(memory)
                memory.seek(0)
                base64_img = "data:image/png;base64," + \
                            base64.b64encode(memory.getvalue()).decode('ascii')
                return render_template("otp_setup.html", code=secret.decode(), qr = base64_img, type="totp", signup = True)
            # if not signing up
            return render_template("otp_setup.html", type="totp", signup = False)


        elif session['2fa_type']=="email":
            #setup 2fa via email, no need to check for signup explicitly because the message is the same.
            return render_template("otp_setup.html", email=session['email'], type="email")
        

    # POST logic
    elif request.method=="POST":
        if 'resend_button' in request.form and session['2fa_type']=='email':
            # email resend
            # regenerate new code
            # generate 6 digit code
            session['attempts']+=0.5
            session['2fa_code']=generate_email_otp()[0]
            if not send_2fa_email(session['email'], session['2fa_code']): # if code unsuccessfully sent:
                # render site
                flash("Email unable to be sent due to unexpected error.", "error")
            return render_template("otp_setup.html", email=session['email'], type="email")
        verified=False 
        # assemble the code back together
        code = request.form['otp1']+request.form['otp2']+request.form['otp3']+request.form['otp4']+request.form['otp5']+request.form['otp6']
        if session['2fa_type']=="totp":
            secret=session['2fa_secret']
            totp = pyotp.TOTP(secret)
            if not code == totp.now():
                #incorrect code
                session['attempts']+=1
                flash("incorrect code entered. Try again.","error")
                return redirect(url_for("authenticate"))
            
            if session['last_action']=='signup':
                # give check if there already exists the account
                if not execute_sql("""SELECT * FROM users WHERE user_email = :email""", {'email' : session['email']}).fetchone():
                    uid=str(uuid.uuid4())
                    name=session["name"]
                    execute_sql("""INSERT INTO users(uid, username, user_email, pwd_hash, secret, two_factor_auth_type, user_score, secret_salt) 
                                VALUES(:uid, :username, :email, :pwd_hash, :secret, :2fa, :userscore, :secret_salt)""", {
                                'uid': uid,
                                'username': session['name'],
                                'email': session['email'],
                                'pwd_hash': session['hashed_password'],                                                                                                                                                                                                                                                                                                                                              
                                'secret': session['encrypted_2fa_secret'],
                                '2fa':"totp",
                                'userscore': 0,
                                "secret_salt":session['secret_salt']})
            else: # if logging in:
                user = execute_sql("""SELECT uid, username FROM users WHERE user_email=:email""", {'email':session['email']}).fetchone() # retrieve uid
                uid=user.uid
                name=user.username
            # 2fa passed
            verified=True

        elif session['2fa_type']=="email":
            if not code == session['2fa_code']:
                #incorrect code
                session['attempts']+=1
                flash("incorrect code entered. Try again","error")
                return redirect(url_for("authenticate"))
            
            if session['last_action']=='signup':
                # give check if there already exists the account
                if not execute_sql("""SELECT * FROM users WHERE user_email = :email""", {'email' : session['email']}).fetchone():
                    uid=str(uuid.uuid4())
                    name=session["name"]
                    execute_sql("""INSERT INTO users(uid, username, user_email, pwd_hash, two_factor_auth_type, user_score) 
                                VALUES(:uid, :username, :email, :pwd_hash, :2fa, :userscore)""", {
                                'uid': uid,
                                'username': session['name'],
                                'email': session['email'],
                                'pwd_hash': session['hashed_password'],
                                '2fa':"email",
                                'userscore': 0})
            else: # if logging in:
                user = execute_sql("""SELECT uid, username FROM users WHERE user_email=:email""", {'email':session['email']}).fetchone() # retrieve uid
                uid=user.uid
                name=user.username

            #2fa passed
            verified=True

    # if code is correct, begin to setup new cookie details
    if verified:
        return login_procedure(uid, name)
    


                                                                           #TODO 2FA SITE TEMPLATE

@app.route("/debug")
def debug():
    return render_template("2fa_email_template.html", code="069420")
if __name__ == "__main__":
    app.run(debug=True)