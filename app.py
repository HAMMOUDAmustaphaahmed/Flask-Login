from flask import Flask, render_template, request, redirect, url_for, flash, session
import logging
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:password@localhost:80/coupe'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max limit

db = SQLAlchemy(app)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    matricule = db.Column(db.Integer)
    role = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Commande(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    article = db.Column(db.String(10), nullable=False)
    commande = db.Column(db.String(20), nullable=False)
    quantite = db.Column(db.Integer)
    date_chargement = db.Column(db.Date)
    type = db.Column(db.String(10))
    etat = db.Column(db.String(20))
    phase = db.Column(db.String(20))
    relaxation = db.Column(db.String(10))
    fiche_matelassage = db.Column(db.String(255))
    document_technique = db.Column(db.String(255))
    information_y = db.Column(db.String(255))

# Authentication and authorization helpers
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['username'] = username
            if user.role.lower() == 'admin':
                return redirect(url_for('admin'))
            elif user.role.lower() == 'cad':
                return redirect(url_for('step1'))
            else:
                flash('Access not allowed for this role.', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        matricule = request.form['matricule']
        role = request.form['role']
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password, matricule=matricule, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully!', 'success')
        return redirect(url_for('admin'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.password = generate_password_hash(request.form['password'], method='sha256')
        user.matricule = request.form['matricule']
        user.role = request.form['role']
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_user.html', user=user)

@app.route('/admin/delete/<int:id>')
@login_required
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Step 1: Formulaire initial
@app.route('/step1', methods=['GET', 'POST'])
@login_required
def step1():
    if request.method == 'POST':
        session['commande'] = request.form.get('commande').strip().upper()
        session['article'] = request.form.get('article').strip().upper()
        session['quantite'] = request.form.get('quantite')
        session['date_chargement'] = request.form.get('date_chargement')
        return redirect(url_for('step2'))
    return render_template('step1.html')

# Step 2: Formulaire étape 2
@app.route('/step2', methods=['GET', 'POST'])
@login_required
def step2():
    if request.method == 'POST':
        session['type'] = request.form.get('type')
        session['phase'] = request.form.get('phase')
        session['relaxation'] = request.form.get('relaxation')

        # Gestion des fichiers uploadés
        fiche_matelassage = request.files.get('fiche_matelassage')
        document_technique = request.files.get('document_technique')

        fiche_matelassage_path = ''
        document_technique_path = ''

        if fiche_matelassage and fiche_matelassage.filename != '':
            fiche_matelassage_path = os.path.join(app.config['UPLOAD_FOLDER'], fiche_matelassage.filename)
            fiche_matelassage.save(fiche_matelassage_path)
            session['fiche_matelassage'] = fiche_matelassage.filename

        if document_technique and document_technique.filename != '':
            document_technique_path = os.path.join(app.config['UPLOAD_FOLDER'], document_technique.filename)
            document_technique.save(document_technique_path)
            session['document_technique'] = document_technique.filename

        return redirect(url_for('step3'))
    return render_template('step2.html')

# Step 3: Formulaire final
@app.route('/step3', methods=['GET', 'POST'])
@login_required
def step3():
    if request.method == 'POST':
        session['information_y'] = request.form.get('information_y')

        # Enregistrement final dans la base de données
        new_commande = Commande(
            article=session.get('article'),
            commande=session.get('commande'),
            quantite=session.get('quantite'),
            date_chargement=session.get('date_chargement'),
            type=session.get('type'),
            phase=session.get('phase'),
            relaxation=session.get('relaxation'),
            fiche_matelassage=session.get('fiche_matelassage'),
            document_technique=session.get('document_technique'),
            information_y=session.get('information_y'),
            etat="en attente"
        )
        db.session.add(new_commande)
        db.session.commit()
        flash('Commande ajoutée avec succès.', 'success')
        session.clear()  # Clear session after final submission
        return redirect(url_for('home'))
    return render_template('step3.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)

