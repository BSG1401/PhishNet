from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
import joblib
import pandas as pd

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key

# Load the trained model
model = joblib.load('phishing_model.pkl')

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'bala',
    'database': 'phishscanner_db'
}

# Initialize database connection
def get_db_connection():
    return mysql.connector.connect(**db_config)

def extract_features(url):
    features = {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_slashes': url.count('/'),
        'num_at': url.count('@'),
        'num_digits': sum(c.isdigit() for c in url),
        'num_letters': sum(c.isalpha() for c in url),
        'num_params': url.count('?'),
        'num_equals': url.count('='),
        'num_hashes': url.count('#'),
        'num_underscores': url.count('_'),
        'num_tildes': url.count('~'),
        'num_ampersands': url.count('&'),
        'num_percent': url.count('%'),
    }
    return features

@app.route('/')
def home():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (email, password) VALUES (%s, %s)', (email, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user[0], password):
            session['email'] = email
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials, please try again.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/predictor', methods=['GET', 'POST'])
def predictor():
    if request.method == 'POST':
        url = request.form['url']
        features = extract_features(url)
        features_df = pd.DataFrame([features])
        prediction = model.predict(features_df)[0]
        result = 'Malicious' if prediction == 1 else 'Legitimate'
        return render_template('predictor.html', result=result, url=url)
    return render_template('predictor.html')

@app.route('/help')
def help():
    return render_template('help.html')

if __name__ == '__main__':
    app.run(debug=True)
