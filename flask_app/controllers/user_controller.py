from flask import flash
from flask import render_template, redirect, session, request
from flask_app.models.users import Users
from flask_app import app
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

# ----render_template---
@app.route("/")
@app.route("/login")
def index():
    return render_template('login.html')

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        return redirect('/logout')
    data = {
        'id': session['user_id']
    }
    return render_template('dashboard.html', user=Users.user_info(data))

# -----Processing----
# -----login----

@app.route("/login/process", methods=['POST'])
def login():
    data = { "email" : request.form["email"] }
    user_from_db = Users.get_by_email(data)
    # user is not registered in the db
    if not user_from_db:
        flash("Invalid Email/Password")
        return redirect("/")
    if not bcrypt.check_password_hash(user_from_db.password, request.form['password']):
        # if we get False after checking the password
        flash("Invalid Email/Password")
        return redirect('/')
    session['id'] = user_from_db.id
    return redirect('/dashboard')

# -------Registration----

@app.route("/login/registration/process", methods = ['POST'])
def save():
    if not Users.validate_register(request.form):
        # redirect to the route where the burger form is rendered.
        return redirect('/')
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    data = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email'],
        'password': request.form['password'],
        'password_confirmation': request.form['password_confirmation'],
        'password': pw_hash
    }
    id = Users.save_registration(data)

    session['id'] = id
    return redirect('/dashboard')
