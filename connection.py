from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from flask_mail import Mail, Message
import sqlite3
import hashlib
import os
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATABASE = 'example.db'

s = URLSafeTimedSerializer(app.secret_key)
# Flask-Mail configuration
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'darlingyashu9424@gmail.com'
app.config['MAIL_PASSWORD'] = 'mgck wlsx dekl sxcv'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                gender TEXT,
                phone_number TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS departments (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS production (
                department_id INTEGER,
                date TEXT,
                produced_quantity INTEGER,
                PRIMARY KEY (department_id, date),
                FOREIGN KEY (department_id) REFERENCES departments(id)
            )
        ''')
        conn.commit()

init_db()

@app.route('/')
def index():
    if 'email' in session:
        return redirect(url_for('main_page'))
    else:
        return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        gender = request.form['gender']
        phone_number = request.form['phone_number']

        if password != confirm_password:
            return "Passwords do not match. Please try again."

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute("INSERT INTO users (email, password, gender, phone_number) VALUES (?, ?, ?, ?)",
                           (email, hashed_password, gender, phone_number))
            db.commit()
        except sqlite3.IntegrityError:
            return "This email is already registered."

        return redirect(url_for('index'))
    else:
        return render_template('signup.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, hashed_password))
    user = cursor.fetchone()

    if user:
        session['email'] = email
        return redirect(url_for('main_page'))
    else:
        return "Invalid credentials. Please try again."

@app.route('/main_page')
def main_page():
    if 'email' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM departments")
        departments = cursor.fetchall()
        return render_template('main_page.html', departments=departments)
    else:
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('index'))

@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        email = request.form['email']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message("Password Reset Request", sender='darlingyashu9424@gmail.com', recipients=[email])
            msg.body = f'Please click the link to reset your password: {reset_url}'
            mail.send(msg)
            flash('A password reset link has been sent to your email.', 'success')
        else:
            flash('Email not found. Please try again.', 'error')
        return redirect(url_for('forget_password'))
    return render_template('forget_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The token is expired.', 'error')
        return redirect(url_for('forget_password'))
    except BadSignature:
        flash('Invalid token.', 'error')
        return redirect(url_for('forget_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        if new_password == confirm_password:
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            db = get_db()
            cursor = db.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
            db.commit()
            flash('Your password has been updated!', 'success')
            return render_template('login.html')
        else:
            flash('Passwords do not match.', 'error')

    return render_template('reset_password.html')


@app.route('/add_department', methods=['GET', 'POST'])
def add_department():
    if request.method == 'POST':
        department_id = request.form['department_id']
        department_name = request.form['department_name']
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM departments WHERE id = ? OR name = ?", (department_id, department_name))
        existing_department = cursor.fetchone()
        
        if existing_department:
            flash("Department ID or Name already exists. Please try again.")
            return redirect(url_for('add_department'))
        
        cursor.execute("INSERT INTO departments (id, name) VALUES (?, ?)", (department_id, department_name))
        db.commit()
        
        return redirect(url_for('main_page'))
    return render_template('add_department.html')

@app.route('/edit_department/<int:department_id>', methods=['GET', 'POST'])
def edit_department(department_id):
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        new_department_id = request.form['department_id']
        department_name = request.form['department_name']
        cursor.execute("UPDATE departments SET id = ?, name = ? WHERE id = ?", (new_department_id, department_name, department_id))
        db.commit()
        return redirect(url_for('main_page'))
    cursor.execute("SELECT * FROM departments WHERE id = ?", (department_id,))
    department = cursor.fetchone()
    return render_template('edit_department.html', department=department)

@app.route('/delete_department/<int:department_id>', methods=['POST'])
def delete_department(department_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM production WHERE department_id = ?", (department_id,))
    cursor.execute("DELETE FROM departments WHERE id = ?", (department_id,))
    db.commit()
    return redirect(url_for('main_page'))

@app.route('/department/<int:department_id>', methods=['GET', 'POST'])
def department_page(department_id):
    if 'email' not in session:
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        date = request.form['date']
        produced_quantity = request.form['production']
        cursor.execute("INSERT INTO production (department_id, date, produced_quantity) VALUES (?, ?, ?)",
                       (department_id, date, produced_quantity))
        db.commit()
        return redirect(url_for('department_page', department_id=department_id))

    cursor.execute("""
        SELECT date, produced_quantity 
        FROM production 
        WHERE department_id = ? 
        ORDER BY date DESC 
        LIMIT 7
    """, (department_id,))
    production_data = cursor.fetchall()

    dates = [row[0] for row in production_data]
    production_values = [row[1] for row in production_data]

    cursor.execute("SELECT name FROM departments WHERE id = ?", (department_id,))
    department_name = cursor.fetchone()[0]
    
    # Fetch production data for the specific department
    cursor.execute("""
        SELECT date, produced_quantity 
        FROM production 
        WHERE department_id = ? 
        ORDER BY date DESC
    """, (department_id,))
    department_production_data = cursor.fetchall()

    return render_template('department_page.html', department_id=department_id, department_name=department_name, dates=dates, production_values=production_values, production_data=department_production_data)
@app.route('/graphs')
def graphs():
    db = get_db()
    cursor = db.cursor()
    # Fetch all departments
    cursor.execute("SELECT id, name FROM departments")
    departments = cursor.fetchall()

    department_data = []
    for department in departments:
        department_id, department_name = department
        cursor.execute("""
            SELECT date, produced_quantity 
            FROM production 
            WHERE department_id = ? 
            ORDER BY date DESC 
            LIMIT 7
        """, (department_id,))
        production_data = cursor.fetchall()

        dates = [row[0] for row in production_data]
        production_values = [row[1] for row in production_data]

        department_data.append({
            'id': department_id,
            'name': department_name,
            'dates': dates,
            'production_values': production_values
        })

    return render_template('graphs.html', departments=department_data)


if __name__ == "__main__":
    app.run(debug=True)
