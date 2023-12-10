from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
from argon2 import PasswordHasher
import os,time

hostName = "localhost"
serverPort = 8080

# Connect to SQLite database for keys storage
conn = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = conn.cursor()

# Create keys table if not exists
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')


# Create users table if not exists
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
''')
               
cursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')

conn.commit()


# Load AES key
AES_SECRET_KEY = os.environ.get('NOT_MY_KEY', '').encode('utf-8')

# Password hasher for Argon2
password_hasher = PasswordHasher()


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()



# Function to register a new user
def register_user(username, email):
    # Generate a secure password 
    password = str(uuid.uuid4())
    
    # Hash the password 
    hashed_password = password_hasher.hash(password)
    
    # Save user details to the database
    cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, hashed_password, email))
    user_id = cursor.lastrowid
    conn.commit()
    
    # Return the generated password
    return {"password": password, "user_id": user_id}

def authenticate_user(username, password):
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result:
        user_id, hashed_password = result
        if password_hasher.verify(hashed_password, password):
            return user_id
    return None


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def save_private_key_to_db(private_key, expiration):
    """Save a private key to the database"""
    serialized_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (serialized_key, expiration))
    conn.commit()




class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        request_ip = self.client_address[0]

        if parsed_path.path == "/auth":
        
            token_payload = None

            # Fetch user ID based on the username in the token_payload

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            user_data = json.loads(post_data.decode('utf-8'))

            username = user_data.get('username')
            password = user_data.get('password')
            print(username)

            if username and password:
                user_id = authenticate_user(username, password)
            if user_id is not None:
                headers = {
                    "kid": "goodKID"
                }
                token_payload = {
                    "user": username,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                }

                # Log authentication request
                request_ip = self.client_address[0]
                cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (request_ip, user_id))
                conn.commit()
          


            print("Authentication request logged:", request_ip, user_id)

            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                save_private_key_to_db(expired_key, int(token_payload["exp"].timestamp()))
            else:
                save_private_key_to_db(private_key, int(token_payload["exp"].timestamp()))

            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
        
        
        elif parsed_path.path == "/register" and self.headers.get('Content-Type') == 'application/json':
            # Handle user registration
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            user_data = json.loads(post_data.decode('utf-8'))

            username = user_data.get('username')
            email = user_data.get('email')

            if username and email:
                result = register_user(username, email)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(json.dumps(result), "utf-8"))
            else:
                self.send_response(400)  # Bad Request
                self.end_headers()
            return

        self.send_response(405)
        self.end_headers()
        return
     

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
