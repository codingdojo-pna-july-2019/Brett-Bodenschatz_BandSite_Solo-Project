import os
from flask import Flask, render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy			
from flask_migrate import Migrate
from sqlalchemy.sql import func	
import stripe
import re


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Artist_Site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

INVALID_PASSWORD_REGEX = re.compile(r'^([^0-9]*|[^A-Z]*)$')

bcrypt = Bcrypt(app)
app.secret_key = "Key_Is_Secret_I_Promise"

# stripe_keys = {
#   'secret_key': os.environ['Tis_a_Secret'],
#   'publishable_key': os.environ['Another_Random_String']
# }

# stripe.api_key = stripe_keys['secret_key']

class Admin(db.Model):
    __tablename__="admins"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    username = db.Column(db.String(255))
    password = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

class Tours(db.Model):
    __tablename__="tours"
    id = db.Column(db.Integer, primary_key=True)
    venue = db.Column(db.String(255))
    location = db.Column(db.String(255))
    date = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin/')
def admin():
    return render_template('admin.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/create_admin', methods=['POST'])
def admins_new():
    valid = True
    
    if len(request.form['first_name']) < 2:
        flash("First name must be longer")
        valid = False

    if len(request.form['last_name']) < 2:
        flash("Last name must be longer")
        valid = False

    if len(request.form['username']) < 3:
        flash("Username must be longer")
        valid = False

    if len(request.form['password']) < 8:
        flash("Password must be at least 8 characters")
        valid = False

    if INVALID_PASSWORD_REGEX.match(request.form['password']):
        flash("Password must have at least one uppercase character and at least one number")
        valid = False
    
    if request.form['password'] != request.form['confirm']:
        flash("Passwords must match")

    if not valid:
        return redirect('/admin/')
        
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    new_admin = Admin(
        first_name=request.form['first_name'], 
        last_name=request.form['last_name'], 
        username=request.form['username'],
        password=pw_hash
    )
    db.session.add(new_admin)
    db.session.commit()
    return redirect('/register')

@app.route('/admin/login', methods=['POST'])
def login_admin():
    valid = True

    if len(request.form['username']) < 1:
        valid = False
        flash("Username cannot be empty")
        

    if len(request.form['password']) < 1:
        valid = False
        flash("Password cannot be empty")
        

    admin = Admin.query.filter_by(username=request.form['username']).first()
    if admin:
        autheticated_user = bcrypt.check_password_hash(admin.password, request.form['password'])
        if autheticated_user:
            session['admin_id'] = admin.id
            return redirect ("/admin_home")

    if not valid:
        return redirect('/admin/')

@app.route('/admin_home')
def admin_home():
    if 'admin_id' not in session:
        return redirect('/')

    return render_template('admin_home.html')

@app.route('/admin_tour')
def admin_tour():
    if 'admin_id' not in session:
        return redirect('/')
    
    all_tours = Tours.query.all()

    return render_template('admin_tour.html', all_tours=all_tours)

@app.route('/add_tour', methods=['POST'])
def your_add():
    if 'admin_id' not in session:
        flash("Please Log In")
        return redirect('/')

    new_tour = Tours(
        venue=request.form['venue'], 
        location=request.form['location'], 
        date=request.form['date']
    )
    db.session.add(new_tour)
    db.session.commit()
    return redirect('/admin_tour')

@app.route("/tours/<tours_id>/delete", methods=['POST'])
def delete_tour(tours_id):
    if 'admin_id' not in session:
        flash("Please Log In")
        return redirect('/')

    tour_to_delete = Tours.query.get(tours_id)
    db.session.delete(tour_to_delete)
    db.session.commit()
    return redirect("/admin_tour")

@app.route("/tours/<tours_id>/edit")
def show_edit(tours_id):
    if 'admin_id' not in session:
        flash("Please Log In")
        return redirect('/')
    
    tour = Tours.query.get(tours_id)
    return render_template("admin_edit.html", tour=tour)

@app.route("/tours/<tours_id>/update", methods=["POST"])
def update_tour(tours_id):
    if 'admin_id' not in session:
        flash("Please Log In")
        return redirect('/')
    
    tour_to_update = Tours.query.get(tours_id)
    tour_to_update.venue=request.form['venue']
    tour_to_update.location=request.form['location']
    tour_to_update.date=request.form['date']
    db.session.commit()
    return redirect("/admin_tour")

@app.route('/merch')
def merch():
    return render_template('merch.html')

@app.route('/listen')
def listen():
    # songs = os.listdir('static/music')
    album1 = os.listdir('static/music/album1')
    album2 = os.listdir('static/music/album2')
    return render_template('listen.html', album1=album1, album2=album2)

@app.route('/tour')
def tour():
    all_tours = Tours.query.all()
    return render_template('tour.html', all_tours=all_tours)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route("/date", methods=['POST'])
def date():
    found = False
    result = Tours.query.filter_by(date=request.form['date']).all()
    if result:
        found = True
    return render_template('partials/date.html', found=found)
    

if __name__ == "__main__":
    app.run(debug=True)