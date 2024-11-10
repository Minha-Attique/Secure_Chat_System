#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <arpa/inet.h>

using namespace std;

#define PORT 8080

int sock;

void create_socket()
{
    sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);

    connect(sock, (struct sockaddr *)&server_address, sizeof(server_address));
}

void registerUser() {
    cout << "\n\t>>> Registration <<<\n";
    string email, username, password;
    cout << "Enter email: ";
    getline(cin, email);
    cout << "Enter username: ";
    getline(cin, username);
    cout << "Enter password: ";
    getline(cin, password);

    // Send registration data to server
    string registrationData = email + "|" + username + "|" + password;
    send(sock, registrationData.c_str(), registrationData.size(), 0);

    // Receive response from server
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    recv(sock, buffer, sizeof(buffer), 0);
    cout << "Server: " << buffer << "\n";
}

int main() {
    cout << "\n\t>>>>>>>>>> XYZ University Client <<<<<<<<<<\n\n";
    create_socket();
    registerUser();
    close(sock);
    return 0;
}
