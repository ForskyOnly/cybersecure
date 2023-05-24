from dotenv import load_dotenv
import os 
from flask import Flask, request, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os 



# # Générer une clé secrète aléatoire
# secret_key = os.urandom(24)

# # Imprimer la clé secrète
# print(secret_key)
# Load environment variables from .env file
load_dotenv()
# print("SECRET_KEY:", os.getenv("SECRET_KEY"))


# Access the secret key
secret_key = os.getenv('SECRET_KEY')




app = Flask(__name__)
app.secret_key = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'test.db')
db = SQLAlchemy(app)


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


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
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





if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
    app.run(debug=True , port ='5001')
