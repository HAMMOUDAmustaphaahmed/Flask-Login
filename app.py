from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/coupe'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/'

db = SQLAlchemy(app)

# Ensure the 'uploads' folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def save_file(file, folder):
    """Save the uploaded file to the specified folder."""
    filename = secure_filename(file.filename)
    file_path = os.path.join(folder, filename)
    file.save(file_path)
    return file_path

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Ensure user is authenticated
        if 'user_id' not in session:
            flash('You must be logged in to upload files.')
            return redirect(url_for('login'))
        
        command_name = request.form.get('command_name')
        fiche_technique = request.files.get('fiche_technique')
        fiche_matelassage = request.files.get('fiche_matelassage')

        if not fiche_technique or not fiche_matelassage:
            flash('Both files are required.')
            return redirect(request.url)
        
        if fiche_technique.filename == '' or fiche_matelassage.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        # Create a folder for the command if it does not exist
        command_folder = os.path.join(app.config['UPLOAD_FOLDER'], command_name)
        if not os.path.exists(command_folder):
            os.makedirs(command_folder)

        # Save the files
        fiche_technique_path = save_file(fiche_technique, command_folder)
        fiche_matelassage_path = save_file(fiche_matelassage, command_folder)

        # Save paths to the database
        new_order = Order(
            commande=command_name,
            fiche_matelassage=fiche_matelassage_path,
            document_technique=fiche_technique_path
        )
        db.session.add(new_order)
        db.session.commit()

        flash('Files successfully uploaded and paths saved to database')
        return redirect(url_for('upload_file'))

    return render_template('cad.html')

# Define models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    matricule = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    commande = db.Column(db.String(255), nullable=False)
    article = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    date_chargement = db.Column(db.Date, nullable=False)
    type = db.Column(db.String(255), nullable=False)
    phase = db.Column(db.String(255))
    relaxation = db.Column(db.String(10), nullable=False)
    fiche_matelassage = db.Column(db.String(255))
    document_technique = db.Column(db.String(255))

    parties = db.relationship('Party', backref='order', lazy=True)

class Party(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    partie_name = db.Column(db.String(255), nullable=False)

    subs = db.relationship('Sub', backref='party', lazy=True)

class Sub(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    party_id = db.Column(db.Integer, db.ForeignKey('party.id'), nullable=False)
    sub_name = db.Column(db.String(255), nullable=False)
    
    temps = db.relationship('Temps', backref='sub', uselist=False)
    matelas = db.relationship('Matelas', backref='sub', lazy=True)

class Temps(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sub_id = db.Column(db.Integer, db.ForeignKey('sub.id'), nullable=False)
    temps_relaxation = db.Column(db.Float, nullable=True)
    temps_matelassage = db.Column(db.Float, nullable=True)
    temps_coupr = db.Column(db.Float, nullable=True)
    temps_etiquetage = db.Column(db.Float, nullable=True)

class Matelas(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sub_id = db.Column(db.Integer, db.ForeignKey('sub.id'), nullable=False)
    longueur = db.Column(db.Numeric(10, 2))
    quantite = db.Column(db.Integer)
    etat = db.Column(db.String(50), nullable=False)

    __table_args__ = (
        db.CheckConstraint(
            "etat IN ('en cours', 'bloqué', 'annulé', 'en prévision')",
            name='check_etat'
        ),
    )

# Create the database tables if they don't exist
with app.app_context():
    db.create_all()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['username'] = username
            session['role'] = user.role
            flash('Login successful!', 'success')
            if user.role == 'admin':
                return redirect(url_for('index'))
            elif user.role == 'cad':
                return redirect(url_for('cad'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/admin')
@login_required
def index():
    if session.get('role') != 'admin':
        flash('You do not have permission to access this page.', 'warning')
        return redirect(url_for('index'))

    users = User.query.all()
    orders = Order.query.all()
    return render_template('index.html', users=users, orders=orders)



@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        matricule = request.form.get('matricule')
        role = request.form.get('role')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, matricule=matricule, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('add_user.html')

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    user = User.query.get_or_404(id)

    if request.method == 'POST':
        user.username = request.form.get('username')
        new_password = request.form.get('password')
        if new_password:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.matricule = request.form.get('matricule')
        user.role = request.form.get('role')
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/cad', methods=['GET', 'POST'])
@login_required
def cad():
    if request.method == 'POST':
        article = request.form.get('article')
        commande = request.form.get('commande')
        date_chargement = request.form.get('date_chargement')
        type_ = request.form.get('type')
        phase = request.form.get('phase')
        relaxation = request.form.get('relaxation')

        fiche_matelassage_filename = None
        document_technique_filename = None

        # Handle file uploads
        fiche_matelassage = request.files.get('fiche_matelassage')
        if fiche_matelassage and fiche_matelassage.filename:
            fiche_matelassage_folder = os.path.join(app.config['UPLOAD_FOLDER'], commande)
            if not os.path.exists(fiche_matelassage_folder):
                os.makedirs(fiche_matelassage_folder)
            fiche_matelassage_filename = save_file(fiche_matelassage, fiche_matelassage_folder)

        document_technique = request.files.get('document_technique')
        if document_technique and document_technique.filename:
            document_technique_folder = os.path.join(app.config['UPLOAD_FOLDER'], commande)
            if not os.path.exists(document_technique_folder):
                os.makedirs(document_technique_folder)
            document_technique_filename = save_file(document_technique, document_technique_folder)

        # Create order
        order = Order(
            article=article,
            commande=commande,
            date_chargement=datetime.strptime(date_chargement, '%Y-%m-%d').date(),
            type=type_,
            phase=phase,
            relaxation=relaxation,
            fiche_matelassage=fiche_matelassage_filename,
            document_technique=document_technique_filename
        )
        db.session.add(order)
        db.session.commit()

        number_of_parties = int(request.form.get('nombre_de_parties', 0))
        for i in range(number_of_parties):
            partie_name = request.form.get(f'partie_nom_{i}')
            part = Party(order_id=order.id, partie_name=partie_name)
            db.session.add(part)
            db.session.commit()

            number_of_subs = int(request.form.get(f'nombre_de_sub_{i}', 0))
            for j in range(number_of_subs):
                sub_name = request.form.get(f'sub_nom_{i}_{j}')
                sub = Sub(party_id=part.id, sub_name=sub_name)
                db.session.add(sub)
                db.session.commit()

                # Handle temps
                temps_relaxation = request.form.get(f'temps_relaxation_{i}_{j}')
                temps_matelassage = request.form.get(f'temps_matelassage_{i}_{j}')
                temps_coupr = request.form.get(f'temps_coupr_{i}_{j}')
                temps_etiquetage = request.form.get(f'temps_etiquetage_{i}_{j}')
                
                # Convert time values to appropriate types
                temps_relaxation = float(temps_relaxation) if temps_relaxation else None
                temps_matelassage = float(temps_matelassage) if temps_matelassage else None
                temps_coupr = float(temps_coupr) if temps_coupr else None
                temps_etiquetage = float(temps_etiquetage) if temps_etiquetage else None

                temps = Temps(
                    sub_id=sub.id,
                    temps_relaxation=temps_relaxation,
                    temps_matelassage=temps_matelassage,
                    temps_coupr=temps_coupr,
                    temps_etiquetage=temps_etiquetage
                )
                db.session.add(temps)
                db.session.commit()

                number_of_matelas = int(request.form.get(f'nombre_de_matelas_{i}_{j}', 0))
                for k in range(number_of_matelas):
                    longueur = request.form.get(f'longueur_{i}_{j}_{k}')
                    quantite = request.form.get(f'quantite_{i}_{j}_{k}')
                    etat = request.form.get(f'etat_{i}_{j}_{k}')
                    
                    # Convert numeric values
                    longueur = float(longueur) if longueur else None
                    quantite = int(quantite) if quantite else None

                    matelas = Matelas(sub_id=sub.id, longueur=longueur, quantite=quantite, etat=etat)
                    db.session.add(matelas)
                    db.session.commit()

        flash('Order added successfully!', 'success')
        return redirect(url_for('cad'))

    return render_template('cad.html')

if __name__ == '__main__':
    app.run(debug=True)
