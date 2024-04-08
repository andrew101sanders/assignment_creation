#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>

#define MAX_INPUT_SIZE 100

void processUser() {
    char userInput[MAX_INPUT_SIZE];
    printf("Enter a username: ");
    fgets(userInput, sizeof(userInput), stdin);
    userInput[strcspn(userInput, "\n")] = '\0';  // Remove trailing newline

    char command[MAX_INPUT_SIZE + 30];
    sprintf(command, "echo 'Processing user: %s'", userInput);  // CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    system(command);
}

void processQuery() {
    char query[MAX_INPUT_SIZE];
    printf("Enter a query: ");
    fgets(query, sizeof(query), stdin);
    query[strcspn(query, "\n")] = '\0';  // Remove trailing newline

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
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = '\0';  // Remove trailing newline

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
    fgets(data, sizeof(data), stdin);
    data[strcspn(data, "\n")] = '\0';  // Remove trailing newline

    char* sanitizedData = strdup(data);  // CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    printf("Sanitized data: %s\n", sanitizedData);
    free(sanitizedData);
}

void processPassword() {
    char password[MAX_INPUT_SIZE];
    printf("Enter a password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';  // Remove trailing newline

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
    fgets(enteredUsername, sizeof(enteredUsername), stdin);
    enteredUsername[strcspn(enteredUsername, "\n")] = '\0';  // Remove trailing newline

    char enteredPassword[MAX_INPUT_SIZE];
    printf("Enter your password: ");
    fgets(enteredPassword, sizeof(enteredPassword), stdin);
    enteredPassword[strcspn(enteredPassword, "\n")] = '\0';  // Remove trailing newline

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