from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

hostName = "localhost"
serverPort = 8080

# DATABASE_ENCRYPTION_KEY = os.environ.get('NOT_MY_KEY')

DATABASE_ENCRYPTION_KEY=b'asdfasdfasdfasdf'
iv = b'asdfasdfasdfasdf'


cipher = Cipher(algorithms.AES(DATABASE_ENCRYPTION_KEY), modes.CBC(iv))
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()

databaseConnection = sqlite3.connect("totally_not_my_privateKeys.db")
keyDBCursor = databaseConnection.cursor()


keyDBCursor.execute('''
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
''')

keyDBCursor.execute('''
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP      
)
''')

keyDBCursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,  
    FOREIGN KEY(user_id) REFERENCES users(id)
);''')



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

def encryptKey(cipher, key):
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    return encryptor.update(padder.update(key) + padder.finalize()) + encryptor.finalize()


def decryptKey(cipher, key):
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decryptor.update(key) + decryptor.finalize()) + unpadder.finalize()





encrypted_pem = encryptKey(cipher, pem)

encrypted_expired_pem = encryptKey(cipher, expired_pem)

currentTime = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

# insert sample data (1 key expired an hour ago, 1 expiring in an hour)
keyDBCursor.execute('''
    INSERT INTO keys (key, exp) VALUES (?1, ?2)''', (encrypted_pem, currentTime + 3600))

keyDBCursor.execute('''
    INSERT INTO keys (key, exp) VALUES (@key, @expire_time)''', (encrypted_expired_pem, currentTime - 3600))



numbers = private_key.private_numbers()



def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def selectKeyRecord(cursor, expired=False):
    if expired: 
        return cursor.execute(' SELECT * FROM keys WHERE exp < ?',
                                             (int(datetime.datetime.now(datetime.timezone.utc).timestamp()),)).fetchone()
    else:
        return cursor.execute(' SELECT * FROM keys WHERE exp > ?',
                                             (int(datetime.datetime.now(datetime.timezone.utc).timestamp()),)).fetchone()
    
def logAuthRequest(cursor, ip, userID):
    cursor.execute('''
        INSERT INTO auth_logs (request_ip, user_id) VALUES (@ip, @userID)
    ''', (ip, userID))


class MyServer(BaseHTTPRequestHandler):
    # all of these request types just bork
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


    #   
    def do_POST(self):
        parsed_path = urlparse(self.path)
        
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            logAuthRequest(keyDBCursor, self.client_address, 3)
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }

            key = None
            
            if 'expired' in params:
                expiredKeyRecord = selectKeyRecord(keyDBCursor, expired=True)

                print("Serving expired key")
                headers["kid"] = str(expiredKeyRecord[0])
                token_payload["exp"] = expiredKeyRecord[2]
                key = decryptKey(cipher,expiredKeyRecord[1])
            else:
                goodKeyRecord = selectKeyRecord(keyDBCursor)
                # Serving good key
                headers["kid"] = str(goodKeyRecord[0])
                token_payload["exp"] = goodKeyRecord[2]
                key = decryptKey(cipher, goodKeyRecord[1])

        


            encoded_jwt = jwt.encode(token_payload, key, algorithm="RS256", headers=headers)


            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        elif parsed_path.path == "/register":
            passowrdResponse = {
                "password": "blah"
            } 
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(passowrdResponse, "utf-8"))
            return
        

        self.send_response(405)
        self.end_headers()
        return
    
    # Reads all valid (non-expired) private keys from the DB. 
    # Creates a JWKS response from those private keys.
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            currentTime = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
            
                    
            # query for expiry times later than current time
            keys = {
                "keys": []
            }

            for i in keyDBCursor.execute('SELECT * FROM keys'):
                if int(i[2]) > currentTime:
                    currentKeyNumbers = serialization.load_pem_private_key(decryptKey(cipher,i[1]), password=None).private_numbers()
                    keys["keys"].append({
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": str(i[0]),
                        "n": int_to_base64(currentKeyNumbers.public_numbers.n),
                        "e": int_to_base64(currentKeyNumbers.public_numbers.e),
                    })
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server up")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    print("Shutting down...")
    databaseConnection.commit()
    databaseConnection.close()

    webServer.server_close()
