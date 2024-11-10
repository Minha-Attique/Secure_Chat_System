#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fstream>
#include <openssl/rand.h>

using namespace std;

#define PORT 8080
#define AES_BLOCK_SIZE 128 / 8

// Store a registered user's details
struct User {
    string email;
    string username;
    string hashed_password;
    string salt;
};

// Function to generate a random salt
string generateSalt() {
    unsigned char salt[4]; // 32-bit salt
    RAND_bytes(salt, sizeof(salt));
    char saltHex[9];
    sprintf(saltHex, "%02x%02x%02x%02x", salt[0], salt[1], salt[2], salt[3]);
    return string(saltHex);
}

// Function to hash password with salt
string hashPassword(const string &password, const string &salt) {
    string saltedPassword = password + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)saltedPassword.c_str(), saltedPassword.size(), hash);

    char hashHex[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(hashHex + (i * 2), "%02x", hash[i]);
    }
    return string(hashHex);
}

// Registration function
void registerUser(int client_socket, const string &shared_key) {
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));

    // Receive and decrypt the registration details
    recv(client_socket, buffer, sizeof(buffer), 0);
    string decryptedData(buffer); // For simplicity, not encrypted here

    // Extract email, username, and password
    string email = decryptedData.substr(0, decryptedData.find('|'));
    string username = decryptedData.substr(email.length() + 1, decryptedData.find('|', email.length() + 1) - email.length() - 1);
    string password = decryptedData.substr(email.length() + username.length() + 2);

    // Check if username already exists in creds.txt
    ifstream infile("creds.txt");
    string line;
    while (getline(infile, line)) {
        if (line.find(username) != string::npos) {
            send(client_socket, "Username already exists!", 25, 0);
            return;
        }
    }
    infile.close();

    // Create salt, hash password and store user
    string salt = generateSalt();
    string hashedPassword = hashPassword(password, salt);

    // Write to file
    ofstream outfile("creds.txt", ios_base::app);
    outfile << email << "|" << username << "|" << hashedPassword << "|" << salt << "\n";
    outfile.close();
    send(client_socket, "Registration successful", 25, 0);
}

int main() {
    cout << "\n\t>>>>>>>>>> XYZ University Server <<<<<<<<<<\n\n";

    // Create the server socket
    int server_socket;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address));
    listen(server_socket, 5);

    int client_socket = accept(server_socket, NULL, NULL);

    // Register a new user
    registerUser(client_socket, "shared_key"); // For simplicity, using dummy key

    close(client_socket);
    close(server_socket);
    return 0;
}
