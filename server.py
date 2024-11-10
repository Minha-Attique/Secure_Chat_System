import socket
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
HOST = '127.0.0.1'
PORT = 65432
CRED_FILE = "creds.txt"
SALT_LENGTH = 32
AES_KEY_SIZE = 16  # 128 bits
PUBLIC_KEY = 19  # Public parameter for Diffie-Hellman (example value)

# Utility Functions
def diffie_hellman(secret_a, secret_b, public_key=PUBLIC_KEY):
    """Calculates the shared secret key using Diffie-Hellman."""
    shared_a = pow(public_key, secret_a, 23)  # mod with prime 23
    shared_b = pow(public_key, secret_b, 23)  # mod with prime 23
    shared_secret = pow(shared_b, secret_a, 23)  # Mutual key
    return shared_secret

def hash_password(password, salt):
    """Hashes the password using SHA-256 and a salt."""
    salted_password = password.encode('utf-8') + salt
    return hashlib.sha256(salted_password).hexdigest()

def store_credentials(email, username, hashed_password, salt):
    """Store user credentials securely in a file."""
    with open(CRED_FILE, 'a') as f:
        f.write(f"{email},{username},{hashed_password},{salt.hex()}\n")

def check_username_uniqueness(username):
    """Check if the username already exists."""
    with open(CRED_FILE, 'r') as f:
        for line in f:
            _, stored_username, _, _ = line.strip().split(',')
            if username == stored_username:
                return False  # Username already exists
    return True

def handle_registration(client_socket, shared_secret):
    """Handle user registration."""
    email = client_socket.recv(1024).decode()
    username = client_socket.recv(1024).decode()
    password = client_socket.recv(1024).decode()

    # Check username uniqueness
    if not check_username_uniqueness(username):
        client_socket.send(b"Username already exists. Choose another.")
        return

    salt = os.urandom(SALT_LENGTH)  # Generate a random salt
    hashed_password = hash_password(password, salt)

    store_credentials(email, username, hashed_password, salt)

    client_socket.send(b"Registration successful.")

def handle_login(client_socket, shared_secret):
    """Handle user login."""
    username = client_socket.recv(1024).decode()
    password = client_socket.recv(1024).decode()

    with open(CRED_FILE, 'r') as f:
        for line in f:
            email, stored_username, stored_hashed_password, stored_salt = line.strip().split(',')
            if username == stored_username:
                salt = bytes.fromhex(stored_salt)
                hashed_password = hash_password(password, salt)
                if hashed_password == stored_hashed_password:
                    client_socket.send(b"Login successful.")
                    return
                else:
                    client_socket.send(b"Incorrect password.")
                    return

    client_socket.send(b"Username not found.")



# Function to handle client communication
def handle_client(client_socket):
    try:
        while True:
            # Send welcome message or prompt for choice
            client_socket.send(b"Do you want to register or login? (Type 'register' or 'login')\n")
            choice = client_socket.recv(1024).decode()

            if choice == "register":
                client_socket.send(b"Enter your email:\n")
                email = client_socket.recv(1024).decode()

                client_socket.send(b"Enter your username:\n")
                username = client_socket.recv(1024).decode()

                client_socket.send(b"Enter your password:\n")
                password = client_socket.recv(1024).decode()

                # Store the registration info (for example, in a dictionary or database)
                # This example just prints it out
                print(f"User registered: {email}, {username}, {password}")
                client_socket.send(b"Registration successful!\n")

            elif choice == "login":
                client_socket.send(b"Enter your username:\n")
                username = client_socket.recv(1024).decode()

                client_socket.send(b"Enter your password:\n")
                password = client_socket.recv(1024).decode()

                # Check login credentials (for now, just prints out)
                print(f"Login attempt: {username}, {password}")
                client_socket.send(b"Login successful!\n")

            else:
                client_socket.send(b"Invalid choice. Try again.\n")

            client_socket.send(b"Do you want to perform another task? (yes/no)\n")
            repeat = client_socket.recv(1024).decode()

            if repeat.lower() != "yes":
                client_socket.send(b"Goodbye!\n")
                break

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()


# Main function to start the server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 5555))
    server.listen(5)
    print("Server started, waiting for clients...")

    while True:
        client_socket, addr = server.accept()
        print(f"Client connected from {addr}")
        handle_client(client_socket)


if __name__ == "__main__":
    start_server()
