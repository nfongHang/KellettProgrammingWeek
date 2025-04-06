from flask import Flask, render_template

# Creating a Flask instance
app = Flask(__name__)
app.config['SECRET_KEY'] = "super secret key skibidi"
# Creating a route decorator
@app.route('/index.php')
def index():
    return 