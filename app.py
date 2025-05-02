from flask import Flask, request, jsonify
from flasgger import Swagger
import sqlite3
import jwt  # vulnerable version
import pickle
from functools import wraps

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

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            token = token.replace("Bearer ", "")
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            # ⚠️ Signature verification is done, but with weak secret
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = data["user"]
        except JWTError:
            return jsonify({"message": "Invalid or expired token!"}), 401
        return f(*args, **kwargs)
    return decorated

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

@app.route('/api/secret', methods=['GET'])
@token_required
def secret_area():
    """
    Protected secret endpoint.
    ---
    tags:
      - secret
    responses:
      200:
        description: Secret data
    """
    return jsonify({"message": f"Welcome {request.user}, here is your secret data!"})


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
# Global insecure in-memory PII store (simulated)
insecure_pii_store = []

@app.route('/pii/submit', methods=['POST'])
def submit_pii():
    """
    Insecure endpoint that accepts and stores personally identifiable information (PII).
    ---
    tags:
      - pii
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              full_name:
                type: string
              email:
                type: string
              ssn:
                type: string
              phone_number:
                type: string
              address:
                type: string
            required: [full_name, email, ssn]
    responses:
      200:
        description: PII processed (insecurely)
        content:
          application/json:
            example:
              message: "PII submitted and logged (insecurely)"
    """
    data = request.json

    # Extracting PII fields explicitly
    full_name = data.get("full_name")
    email = data.get("email")
    ssn = data.get("ssn")
    phone_number = data.get("phone_number")
    address = data.get("address")

    # ❌ Insecure: Logging PII to stdout
    print(f"[INSECURE LOG] Received PII Data:\n"
          f"  Name: {full_name}\n"
          f"  Email: {email}\n"
          f"  SSN: {ssn}\n"
          f"  Phone: {phone_number}\n"
          f"  Address: {address}")

    # ❌ Insecure: Storing PII in global memory
    insecure_pii_store.append({
        "full_name": full_name,
        "email": email,
        "ssn": ssn,
        "phone_number": phone_number,
        "address": address
    })
    return jsonify({"message": "PII submitted and logged (insecurely)"}), 200

def get_instance_metadata(path):
    try:
        url = f"http://169.254.169.254/latest/meta-data/{path}"
        response = requests.get(url, timeout=2)
        return response.text
    except:
        return None

def get_cloud_metadata():
    try:
        region = get_instance_metadata("placement/region") or "us-east-1"
        ec2 = boto3.resource("ec2", region_name=region)

        instance_id = get_instance_metadata("instance-id")
        instance_type = get_instance_metadata("instance-type")
        ami_id = get_instance_metadata("ami-id")
        az = get_instance_metadata("placement/availability-zone")

        running_instances = list(ec2.instances.filter(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ))

        return {
            "cloud_provider": "AWS",
            "instance_id": instance_id,
            "instance_type": instance_type,
            "ami_id": ami_id,
            "availability_zone": az,
            "region": region,
            "running_instance_count": len(running_instances),
            "usage_score": 90
        }

    except Exception as e:
        # Fallback when not in AWS
        return {
            "cloud_provider": "AWS",
            "region": "us-east-1",
            "instance_id": "local-testing",
            "instance_type": "t2.micro",
            "availability_zone": "us-east-1a",
            "usage_score": 20,
            "note": "Fallback mock data. Likely running outside AWS."
        }

@app.route('/info', methods=['GET'])
def cloud_info():
    """
    Returns dynamic cloud metadata for scoring.
    ---
    tags:
      - metadata
    responses:
      200:
        description: AWS cloud metadata
        content:
          application/json:
            example:
              cloud_provider: "AWS"
              instance_id: "i-0abc1234"
              instance_type: "t2.micro"
              ami_id: "ami-0abcdef"
              region: "us-east-1"
              availability_zone: "us-east-1a"
              running_instance_count: 3
              usage_score: 90
    """
    return jsonify(get_cloud_metadata())

if __name__ == '__main__':
    app.run(debug=True)
