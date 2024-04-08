#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <dbi/dbi.h>
#include <random>

void processUser() {
    char userInput[100];
    printf("Enter a username: ");
    scanf("%s", userInput);  // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

    char command[130];
    sprintf(command, "echo 'Processing user: %s'", userInput);  // CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    system(command);
}

void processQuery() {
    char query[100];
    printf("Enter a query: ");
    scanf("%s", query);  // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

    char sql[150];
    sprintf(sql, "SELECT * FROM users WHERE username = '%s'", query);  // CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    printf("Executing SQL: %s\n", sql);
}

void processNumber() {
    int number;
    printf("Enter a number: ");
    scanf("%d", &number);

    int array[10];
    array[number] = 42;  // CWE-120: Buffer Overflow
    printf("Number processed: %d\n", number);
}

void processFile() {
    char filename[100];
    printf("Enter a filename: ");
    scanf("%s", filename);  // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

    FILE* file = fopen(filename, "r");  // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    if (file != NULL) {
        char buffer[100];
        fgets(buffer, sizeof(buffer), file);
        printf("File content: %s\n", buffer);
        fclose(file);
    } else {
        printf("Failed to open the file.\n");
    }
}

void processData() {
    char data[100];
    printf("Enter some data: ");
    scanf("%s", data);  // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

    char* sanitizedData = strdup(data);  // CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    printf("Sanitized data: %s\n", sanitizedData);
    free(sanitizedData);
}

void processPassword() {
    char password[100];
    printf("Enter a password: ");
    scanf("%s", password);  // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

    unsigned char hashedPassword[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)password, strlen(password), hashedPassword);  // CWE-759: Use of a One-Way Hash without a Salt

    char hashedPasswordStr[MD5_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&hashedPasswordStr[i * 2], "%02x", hashedPassword[i]);
    }
    hashedPasswordStr[MD5_DIGEST_LENGTH * 2] = '\0';

    printf("Hashed password: %s\n", hashedPasswordStr);
}

void authenticateUser() {
    char enteredUsername[100];
    printf("Enter your username: ");
    scanf("%s", enteredUsername);  // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

    char enteredPassword[100];
    printf("Enter your password: ");
    scanf("%s", enteredPassword);  // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

    const char* username = "admin";  // CWE-798: Use of Hard-coded Credentials
    const char* password = "password123";  // CWE-798: Use of Hard-coded Credentials

    if (strcmp(enteredUsername, username) == 0 && strcmp(enteredPassword, password) == 0) {
        printf("Authentication successful. Welcome, admin!\n");
    } else {
        printf("Authentication failed. Invalid username or password.\n");
    }
}

void connectToDatabase() {
    dbi_conn conn = dbi_conn_new("mysql");
    const char* password = "secret";  // CWE-798: Use of Hard-coded Credentials
    dbi_conn_set_option(conn, "password", password);  // CWE-259: Use of Hard-coded Password
    dbi_conn_set_option(conn, "username", "admin");  // CWE-798: Use of Hard-coded Credentials

    dbi_conn_connect(conn);

    // Perform database operations...

    dbi_conn_close(conn);
}

void generateSecretToken() {
    int secretToken = std::rand();  // CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    printf("Secret token: %d\n", secretToken);
}

int main() {
    processUser();
    processQuery();
    processNumber();
    processFile();
    processData();
    processPassword();
    authenticateUser();
    connectToDatabase();
    generateSecretToken();

    return 0;
}