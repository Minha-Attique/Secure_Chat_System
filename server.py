import socket
import threading

HOST = '127.0.0.1'
PORT = 65432

# Handles messages from one client to another
def handle_client(client_socket, client_address, other_client_socket):
    print(f"Client {client_address} connected.")
    while True:
        try:
            # Receive message from the client
            message = client_socket.recv(1024).decode()
            if message.lower() == 'bye':
                print(f"Client {client_address} has left the chat.")
                break

            print(f"Message from {client_address}: {message}")
            
            # Send the message to the other client
            if other_client_socket:
                other_client_socket.send(f"{client_address}: {message}".encode())

        except Exception as e:
            print(f"Error with client {client_address}: {e}")
            break

    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(2)
    print("Server started. Waiting for clients...")

    # Accept two clients
    client1, addr1 = server.accept()
    client2, addr2 = server.accept()

    # Start a thread for each client
    thread1 = threading.Thread(target=handle_client, args=(client1, addr1, client2))
    thread2 = threading.Thread(target=handle_client, args=(client2, addr2, client1))

    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()
    print("Server shutting down.")

if __name__ == "__main__":
    start_server()
