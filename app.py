from flask import Flask, request, jsonify
from flasgger import Swagger
import sqlite3
import jwt  # vulnerable version
import pickle

app = Flask(__name__)
app.config['SWAGGER'] = {
    'title': 'Vulnerable Flask API',
    'uiversion': 3
}
Swagger(app)

SECRET_KEY = 'supersecretkey'  # hardcoded secret

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    conn.commit()
    conn.close()

init_db()

# ---------- Swagger Documented Endpoints ----------

@app.route('/login', methods=['POST'])
def login():
    """
    Login endpoint vulnerable to SQL Injection
    ---
    parameters:
      - name: username
        in: formData
        type: string
        required: true
      - name: password
        in: formData
        type: string
        required: true
    responses:
      200:
        description: Login status
    """
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = c.execute(query).fetchone()
    conn.close()
    if result:
        return jsonify({"msg": "Logged in!"})
    else:
        return jsonify({"msg": "Invalid credentials"}), 401

@app.route('/xss', methods=['GET'])
def xss():
    """
    Endpoint vulnerable to XSS
    ---
    parameters:
      - name: input
        in: query
        type: string
        required: true
    responses:
      200:
        description: Returns the input
    """
    user_input = request.args.get('input')
    return f"<h1>{user_input}</h1>"

@app.route('/jwt', methods=['POST'])
def generate_jwt():
    """
    Generates a JWT using vulnerable dependency
    ---
    parameters:
      - name: user
        in: formData
        type: string
        required: true
    responses:
      200:
        description: JWT Token
    """
    user = request.form['user']
    token = jwt.encode({"user": user}, SECRET_KEY)
    return jsonify(token=token)

# ---------- Hidden / Undocumented Endpoints ----------

@app.route('/pickle', methods=['POST'])
def insecure_pickle():
    data = request.data
    try:
        obj = pickle.loads(data)
        return jsonify({"msg": "Deserialized successfully", "data": str(obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/secret-info', methods=['GET'])
def secret_info():
    return jsonify({"flag": "FLAG{you_found_a_hidden_endpoint}"})

if __name__ == '__main__':
    app.run(debug=True)
