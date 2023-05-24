from flask import Flask, request, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import generate_password_hash, check_password_hash
import hashlib
import os 

app = Flask(__name__)
app.secret_key = 'super secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'test.db')
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    hashed_saled_password = db.Column(db.String(128), nullable=False)


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

        # Hachage du mot de passe avec la méthode SHA-256 sans salage
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        new_user = User(username=username, password=password, hashed_saled_password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return 'Inscription réussie !'
    else:
        return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.hashed_saled_password, password):
            session['username'] = user.username
            return 'Connexion réussie !'
        else:
            return 'Mot de passe ou nom d\'utilisateur incorrect'
    else:
        return render_template('login.html')
 

    
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



#_____________________________________________________Create Rainbow table____________________________________________________

# Liste de mots de passe courants
mots_de_passe = [ 123456,  "password",  123456789, 12345678, 12345, 111111, 1234567, "sunshine", "qwerty", "iloveyou", "princess", "admin", "welcome", 666666, "abc123", "football", 123123,
    "monkey",  654321,  "!@#$%^&*", "charlie", "aa123456", "donald",  "password1", "qwerty123", "letmein", "zxcvbnm", "login",
    "starwars", 121212, "bailey", "freedom", "shadow", "passw0rd", "master", "baseball",
    "buster","Daniel","Hannah","Thomas","summer", "George", "Harley", 222222, "Jessica", "ginger", "abcdef",
    "Jordan", 55555, "Tigger", "Joshua", "Pepper", "Robert", "Matthew", 12341234,
    "Andrew", "lakers", "andrea", "1qaz2wsx", "sophie", "Ferrari", "Cheese", "Computer", "jesus", "Corvette", "Mercedes", "flower", "Blahblah",
    "Maverick", "Hello", "loveme", "nicole", "hunter", "amanda", "jennifer",
    "banana", "chelsea", "ranger",
    "trustno1",  "merlin",  "cookie",  "ashley",  "bandit",  "killer",  "aaaaaa",  "1q2w3e",  "zaq1zaq1",  "mustang",
    "test", "hockey", "dallas", "whatever", "admin123", "michael", "liverpool",
    "querty","william","soccer","london","!@#$%^&amp;","trustnot","dragon","adobe123",
    1234, 1234567890
]



# Rainbow table (dictionnaire vide)
rainbow_table = {}

# Boucle pour hacher les mots de passe
for mot_de_passe in mots_de_passe:
    # Convertir le mot de passe en une chaîne de caractères
    mot_de_passe = str(mot_de_passe)
    
    # Calculer le hachage SHA-256 du mot de passe
    hachage = hashlib.sha256(mot_de_passe.encode()).hexdigest()
    
    # Ajouter le hachage et le mot de passe à la rainbow table
    rainbow_table[hachage] = mot_de_passe

# Mot de passe à rechercher (haché)
mot_de_passe_recherche = "b493d48364afe44d11c0165cf470a4164d1e2609911ef998be868d46ade3de4e"

# Recherche dans la rainbow table
if mot_de_passe_recherche in rainbow_table:
    print("Le mot de passe existe dans la rainbow table.")
else:
    print("Le mot de passe n'existe pas dans la rainbow table.")

#______________________________________________________________________________________________________________________________

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
    app.run(debug=True , port ='5001')
