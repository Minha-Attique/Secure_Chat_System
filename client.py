import socket
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Constants
HOST = '127.0.0.1'
PORT = 65432
AES_KEY_SIZE = 16  # 128 bits

# Utility Functions
def diffie_hellman(secret_a, secret_b, public_key=19):
    """Calculates the shared secret key using Diffie-Hellman."""
    shared_a = pow(public_key, secret_a, 23)  # mod with prime 23
    shared_b = pow(public_key, secret_b, 23)  # mod with prime 23
    shared_secret = pow(shared_b, secret_a, 23)  # Mutual key
    return shared_secret

def aes_encrypt(data, key):
    """Encrypt data using AES (CBC mode)."""
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext

def aes_decrypt(data, key):
    """Decrypt AES data."""
    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')

def register(client_socket):
    """Client-side registration."""
    email = input("Enter your email: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    client_socket.send(b'register')
    client_socket.send(email.encode())
    client_socket.send(username.encode())
    client_socket.send(password.encode())

    response = client_socket.recv(1024).decode()
    print(response)

def login(client_socket):
    """Client-side login."""
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    client_socket.send(b'login')
    client_socket.send(username.encode())
    client_socket.send(password.encode())

    response = client_socket.recv(1024).decode()
    print(response)

import socket

# Function to communicate with the server
def communicate_with_server():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 5555))

    try:
        while True:
            # Get choice from the server (register/login)
            choice = input("Do you want to register or login? ")
            client.send(choice.encode())

            if choice == "register":
                email = input("Enter your email: ")
                client.send(email.encode())

                username = input("Enter your username: ")
                client.send(username.encode())

                password = input("Enter your password: ")
                client.send(password.encode())

                response = client.recv(1024).decode()
                print(response)

            elif choice == "login":
                username = input("Enter your username: ")
                client.send(username.encode())

                password = input("Enter your password: ")
                client.send(password.encode())

                response = client.recv(1024).decode()
                print(response)

            else:
                print("Invalid choice. Please type 'register' or 'login'.")

            # Ask if they want to perform another task
            repeat = input("Do you want to perform another task? (yes/no): ")
            client.send(repeat.encode())

            if repeat.lower() != "yes":
                print("Goodbye!")
                break

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    communicate_with_server()
