#include <iostream>
#include <string>
#include <cstdio>
#include <openssl/md5.h>

void processUser() {
    std::string userInput;
    std::cout << "Enter a username: ";
    std::getline(std::cin, userInput);

    std::string command = "echo 'Processing user: " + userInput + "'";  // CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    std::system(command.c_str());
}

void processQuery() {
    std::string query;
    std::cout << "Enter a query: ";
    std::getline(std::cin, query);

    std::string sql = "SELECT * FROM users WHERE username = '" + query + "'";  // CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    std::cout << "Executing SQL: " << sql << std::endl;
}

void processNumber() {
    int number;
    std::cout << "Enter a number: ";
    std::cin >> number;

    int array[10];
    array[number] = 42;  // CWE-120: Buffer Overflow
    std::cout << "Number processed: " << number << std::endl;
}

void processFile() {
    std::string filename;
    std::cout << "Enter a filename: ";
    std::getline(std::cin, filename);

    std::FILE* file = std::fopen(filename.c_str(), "r");  // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    if (file != NULL) {
        char buffer[100];
        std::fgets(buffer, sizeof(buffer), file);
        std::cout << "File content: " << buffer << std::endl;
        std::fclose(file);
    } else {
        std::cout << "Failed to open the file." << std::endl;
    }
}

void processData() {
    std::string data;
    std::cout << "Enter some data: ";
    std::getline(std::cin, data);

    std::string sanitizedData = data;  // CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    std::cout << "Sanitized data: " << sanitizedData << std::endl;
}

void processPassword() {
    std::string password;
    std::cout << "Enter a password: ";
    std::getline(std::cin, password);

    unsigned char hashedPassword[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)password.c_str(), password.length(), hashedPassword);  // CWE-759: Use of a One-Way Hash without a Salt

    char hashedPasswordStr[MD5_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        std::sprintf(&hashedPasswordStr[i * 2], "%02x", hashedPassword[i]);
    }
    hashedPasswordStr[MD5_DIGEST_LENGTH * 2] = '\0';

    std::cout << "Hashed password: " << hashedPasswordStr << std::endl;
}

void authenticateUser() {
    std::string enteredUsername;
    std::cout << "Enter your username: ";
    std::getline(std::cin, enteredUsername);

    std::string enteredPassword;
    std::cout << "Enter your password: ";
    std::getline(std::cin, enteredPassword);

    std::string username = "admin";
    std::string password = "password123";

    if (enteredUsername == username && enteredPassword == password) {  // CWE-798: Use of Hard-coded Credentials
        std::cout << "Authentication successful. Welcome, admin!" << std::endl;
    } else {
        std::cout << "Authentication failed. Invalid username or password." << std::endl;
    }
}

int main() {
    processUser();
    processQuery();
    processNumber();
    processFile();
    processData();
    processPassword();
    authenticateUser();

    return 0;
}