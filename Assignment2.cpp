#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>

#define MAX_INPUT_SIZE 100

void processUser() {
    char userInput[MAX_INPUT_SIZE];
    printf("Enter a username: ");
    scanf("%s", userInput);  // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

    char command[MAX_INPUT_SIZE + 30];
    sprintf(command, "echo 'Processing user: %s'", userInput);  // CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    system(command);
}

void processQuery() {
    char query[MAX_INPUT_SIZE];
    printf("Enter a query: ");
    scanf("%s", query);  // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

    char sql[MAX_INPUT_SIZE + 50];
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
    char filename[MAX_INPUT_SIZE];
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
    char data[MAX_INPUT_SIZE];
    printf("Enter some data: ");
    scanf("%s", data);  // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

    char* sanitizedData = strdup(data);  // CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    printf("Sanitized data: %s\n", sanitizedData);
    free(sanitizedData);
}

void processPassword() {
    char password[MAX_INPUT_SIZE];
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
    char enteredUsername[MAX_INPUT_SIZE];
    printf("Enter your username: ");
    scanf("%s", enteredUsername);  // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

    char enteredPassword[MAX_INPUT_SIZE];
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