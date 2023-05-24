from flask import Flask, request, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'super secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return 'Registered successfully'
    else:
        return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username, password=password).first()

        if user:
            session['username'] = user.username
            return 'Logged in successfully'
        else:
            return 'Invalid credentials'
    else:
        return render_template('login.html')
    
@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('login'))



@app.route('/admin')
def admin_page():
    if 'username' in session:
        users = User.query.all()
        return render_template('admin.html', users=users)
    else:
        return 'Unauthorized'



if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create the database
    app.run(debug=True)