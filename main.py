from dotenv import load_dotenv
import os 
from flask import Flask, request, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os 
import secrets

# app = Flask(__name__)
# app.secret_key = secrets.token_hex(16)  # Clé secrète pour signer les cookies de session

# @app.route('/')
# def index():
#     if 'session_id' not in session:
#         session['session_id'] = secrets.token_hex(16)  # Génère un ID de session aléatoire
#     return 'Hello, World!'
    
# -------------------------------------------------------------------------------------------------------------------------------------
# Pour assurer la sécurité des cookies de session dans votre application Flask, vous pouvez suivre les bonnes pratiques suivantes :
# ----------------------------------------------------------------------------------------------------------------------------------------
# # Générer une clé secrète aléatoire
# secret_key = os.urandom(24)
# # Imprimer la clé secrète
# print(secret_key)
# Puis la sauveguarder dans un fichier .env
# ------------------------------------------------------------

# Load environment variables from .env file
load_dotenv()
# print("SECRET_KEY:", os.getenv("SECRET_KEY"))

# Access the secret key
secret_key = os.getenv('SECRET_KEY')


app = Flask(__name__)
app.secret_key = secret_key
# -------------------------------------------------------
# Utiliser des cookies sécurisés : Définissez l'attribut secure sur les cookies de session afin qu'ils ne soient envoyés que via des connexions HTTPS 
# sécurisées. Cela empêche les cookies d'être transmis sur des connexions non sécurisées, réduisant ainsi le risque d'interception par des attaquants.
app.config['SESSION_COOKIE_SECURE'] = True
# Utiliser des cookies avec l'attribut HttpOnly : Définissez l'attribut HttpOnly sur les cookies de session pour empêcher l'accès via JavaScript. 
# Cela protège les cookies contre les attaques de type cross-site scripting (XSS) où du code malveillant pourrait essayer de voler les cookies via 
# des scripts côté client.
app.config['SESSION_COOKIE_HTTPONLY'] = True
# Définir une expiration appropriée : Configurez la durée de vie des cookies de session en utilisant l'attribut permanent_session_lifetime pour 
# définir une expiration appropriée. Cela limite la durée de validité des cookies et réduit le risque d'utilisation abusive.
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Exemple : 7 jours

# ---------------------------------------------------------

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'test.db')
db = SQLAlchemy(app)

# ----------------------------------------------------------------------------------------------------
@app.route('/')
def index():
    # Générer un identifiant de session aléatoire
    session['session_id'] = secrets.token_hex(16)
    return 'Session ID generated!'

# ----------------------------------------------------------------------------------------------
# # On peut régénérer périodiquement les ID de session. Cela réduit les risques d'attaque par fixation de session. 
# from flask import session

# @app.route('/')
# def index():
#     if 'session_id' not in session:
#         session['session_id'] = secrets.token_hex(16)  # Génère un ID de session aléatoire
#     else:
#         # Régénère l'ID de session
#         session.regenerate()
#     return 'Hello, World!'
# -----------------------------------------------------------------------------------------------


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


@app.route('/home')
def home():
    return render_template('home.html')



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Salage et hachage du mot de passe avec un sel aléatoire
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return 'Inscription réussie !'
    else:
        return render_template('signup.html')
# -------------------------------------------------------------------------------
# # Sans limiter le nombre de tentatives de connexion
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')

#         user = User.query.filter_by(username=username).first()

#         if user and check_password_hash(user.password, password):
#             session['username'] = user.username
#             return 'Connexion réussie !'
#         else:
#             return 'Mot de passe ou nom d\'utilisateur incorrect'
#     else:
#         return render_template('login.html')
# ---------------------------------------------------------------------------------
# # On peut vérifier le nombre de tentatives de connexion par utilisateur. Si le nombre de tentatives dépasse ou est égal à 3, il renvoie 
# un message indiquant qu'il y a eu trop de tentatives de connexion.
login_attempts = {}  # Dictionary to store login attempts count by username

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        
        # Check if login attempts count exists for the username, initialize to 0 if not
        if username not in login_attempts:
            login_attempts[username] = 0
        
        if login_attempts[username] >= 3:
            return "Trop de tentatives de connexion pour l'utilisateur {}. Veuillez réessayer plus tard.".format(username)

        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            login_attempts.pop(username)  # Reset login attempts for the successful user
            return 'Connexion réussie !'
        else:
            login_attempts[username] += 1
            return 'Mot de passe ou nom d\'utilisateur incorrect'
    else:
        return render_template('login.html')
#-----------------------------------------------


    
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))



@app.route('/admin')
def admin_page():
    if 'username' in session:
        users = User.query.all()
        return render_template('admin.html', users=users)
    else:
        return 'NOOOOOOOOOOOO'





if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
    app.run(debug=True , port ='5001')
