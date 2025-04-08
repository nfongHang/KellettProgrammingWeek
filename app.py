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
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from io import BytesIO
import qrcode
# Creating a Flask instance
app = Flask(__name__)
# Add the databases
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:[insert_very_real_password_here]@localhost/main"
app.config['SECRET_KEY'] = "skibidi/skibidi/hawk/tuah/hawk"

# Create engine
engine = create_engine("mysql+pymysql://root:[dude_im_not_pushing_my_real_password_lmao]@localhost/main")



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
                secret = TODO
                if not "DECRYPTED" in str(secret)[-9:]:
                    flash("Secret key was not decrypted properly", "error")
                    return redirect(url_for("login"))
                
                session['2fa_secret'] = secret
                session['2fa_required'] = True                                                                  # saves whether if user needs to do a 2fa or not.
                session['2fa_type'] = user.two_factor_auth_type
                
                session['2fa_expiry'] = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5))         # set timeout/expiry of 2fa secret
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
        encrypted_secret=None
        session['2fa_required'] = False 
        if "2fa_type" in request.form: # if user wants to have 2fa:
            kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=480000,
            # potentially dangerous?
            backend = default_backend()
            )
            if request.form["2fa_type"]=="totp":
                # creating secret key for user
                secret=generate_2fa_secret() 
                session['2fa_secret'] = secret
                # encrypt 2fa secret here in order to keep the password always within signup page and isnt stored afterwards.
                key=base64.urlsafe_b64encode(kdf.derive(password)) # key derived using password
                session['encrypted_2fa_secret'] = Fernet(key).encrypt(secret) # encrypted
                session['2fa_expiry'] = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5))
                session['2fa_type'] = "totp"
            # hashing the password using bcrypt
            
            session['2fa_required'] = True                                                                  # saves whether if user needs to do a 2fa or not.
        hashed_password = bcrypt.hashpw(password, salt)
        session['uid'] = None                                                                           # general user information. UID should only be generated when the account is confirmed to be created.
        session['email'] = email                                                                        #
        session['last_action'] = "signup" 
        
        if session['2fa_required'] == False:
            return redirect(url_for("/")) #return to home page
        else:
            return redirect(url_for("setup_2fa"))
        #execute_sql("""INSERT INTO users(uid, username, user_email, pwd_hash, secret) VALUES(:uid, :username, :email, :pwd_hash, :secret)""", {
        #'uid': 0 ,  # Should this be auto-incremented instead?
        #'username': name,
        #'email': email,
        #'pwd_hash': hashed_password,                                                                                                                                                                                                                                                                                                                                              
        #'secret': encrypted_secret})
    else:
        print('a')
        return render_template("signup.html")

@app.route("/setup_2fa")
def setup_2fa( ):
    if session['2fa_type']=="totp":
        #setup totp
        memory = BytesIO()
        secret=session['2fa_secret']
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name = session['email'], issuer_name="Kellett Programming Week")
        img = qrcode.make(provisioning_uri)
        img.save(memory)
        memory.seek(0)
        base64_img = "data:image/png;base64," + \
                     base64.b64encode(memory.getvalue()).decode('ascii')
        return render_template("totp_setup.html", code=secret.decode(), qr = base64_img)

    
    elif session['2fa_type']=="email":
        #setup 2fa via email
        pass
        

@app.route("/verify", methods=["GET","POST"])
def verify():
    print("hhhh")
    # checks if there is a valid session
    if 'uid' not in session:
        return redirect(url_for("/" if not ('last_action' in session) else (session['last_action'])))       #redirect to home page or login or signup depending on last action
    
    # check for 2fa expiry
    if datetime.datetime.now(datetime.timezone.utc) >= session["2fa_expiry"]:
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


if __name__ == "__main__":
    app.run(debug=True)