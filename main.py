# from flask import Flask, request, session, render_template, redirect, url_for
# from flask_sqlalchemy import SQLAlchemy
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
# import os 
# from flask_bcrypt import Bcrypt





# app = Flask(__name__)
# app.secret_key = 'super secret key'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'test.db')
# db = SQLAlchemy(app)

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     password = db.Column(db.String(120), nullable=False)

#     def __repr__(self):
#         return '<User %r>' % self.username


# @app.route('/home')
# def home():
#     return render_template('home.html')



# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')

#         new_user = User(username=username, password=password)
#         db.session.add(new_user)
#         db.session.commit()

#         return 'inscritpion reussi !'
#     else:
#         return render_template('signup.html')


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')

#         user = User.query.filter_by(username=username, password=password).first()

#         if user:
#             session['username'] = user.username
#             return 'connexion reussi !'
#         else:
#             return 'mdp ou username incorrect'
#     else:
#         return render_template('login.html')
    
# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     return redirect(url_for('login'))



# @app.route('/admin')
# def admin_page():
#     if 'username' in session:
#         users = User.query.all()
#         return render_template('admin.html', users=users)
#     else:
#         return 'NOOOOOOOOOOOO'



# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()  
#     app.run(debug=True)






# hydra -l admin -P /home/apprenant/Documents/01projet_python/DevIA_Roubaix/cybersecure/password.txt -s 5000 -f 127.0.0.1 http-post-form "/login:username=^USER^&password=^PASS^:F=mdp ou username incorrect" -V


#######################################################################################################################################################################
#                                                                      SECURISÉ
#######################################################################################################################################################################
from flask import Flask, request, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

app = Flask(__name__)
app.secret_key = 'super secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'test.db')
db = SQLAlchemy(app)

limiter = Limiter(key_func=get_remote_address, default_limits=["5 per minute", "50 per hour", "500 per day"])
limiter.init_app(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    login_attempts = db.Column(db.Integer, default=0)

    def __repr__(self):
        return '<User %r>' % self.username

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = generate_password_hash(request.form.get('password'), method='sha256')

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return 'inscription réussi !'
    else:
        return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute") 
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user:
            if check_password_hash(user.password, password):
                if user.login_attempts < 5:  
                    session['username'] = user.username
                    user.login_attempts = 0  
                    db.session.commit()
                    return 'connexion réussi !'
                else:
                    return 'Ce compte a été verrouillé suite à plusieurs tentatives de connexion échouées.'
            else:
                user.login_attempts += 1  
                db.session.commit()
                return 'mot de passe ou username incorrect'
        else:
            return 'mot de passe ou username incorrect'
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
    app.run(debug=True)
