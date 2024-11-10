import socket
import threading

HOST = '127.0.0.1'
PORT = 65432

# Function to receive messages
def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            print(message)
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    print("Connected to the chat server. Type 'bye' to exit.")

    # Start a thread to listen for incoming messages
    receive_thread = threading.Thread(target=receive_messages, args=(client,))
    receive_thread.start()

    while True:
        message = input()
        if message.lower() == 'bye':
            client.send('bye'.encode())
            break

        client.send(message.encode())

    client.close()
    print("Disconnected from the chat server.")

if __name__ == "__main__":
    start_client()
