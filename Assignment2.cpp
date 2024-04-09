#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <random>

void processUser() {
    char userInput[100];
    printf("Enter a username: ");
    scanf("%s", userInput);
    // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
    char command[130];
    sprintf(command, "echo 'Processing user: %s'", userInput);
    // CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    system(command);
}

void processQuery() {
    char query[100];
    printf("Enter a query: ");
    scanf("%s", query);
    // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
    char sql[150];
    sprintf(sql, "SELECT * FROM users WHERE username = '%s'", query);
    // CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    printf("Executing SQL: %s\n", sql);
}

void processNumber() {
    int number;
    printf("Enter a number: ");
    scanf("%d", &number);
    int array[10];
    array[number] = 42;
    // CWE-120: Buffer Overflow
    printf("Number processed: %d\n", number);
}

void processFile() {
    char filename[100];
    printf("Enter a filename: ");
    scanf("%s", filename);
    // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
    FILE* file = fopen(filename, "r");
    // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    if (file != NULL) {
        char buffer[100];
        fgets(buffer, sizeof(buffer), file);
        printf("File content: %s\n", buffer);
        fclose(file);
    } else {
        printf("Failed to open the file.\n");
    }
}

void processPassword() {
    char password[100];
    printf("Enter a password: ");
    scanf("%s", password);
    // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
    std::hash<std::string> hasher;
    size_t hashedPassword = hasher(password);
    // CWE-759: Use of a One-Way Hash without a Salt
    printf("Hashed password: %zu\n", hashedPassword);
}

void connectToDatabase() {
    const char* hardcodedUsername = "admin";
    const char* hardcodedPassword = "secret";
    // CWE-798: Use of Hard-coded Credentials

    // Simulating a database connection
    printf("Connecting to the database...\n");
    printf("Using username: %s\n", hardcodedUsername);
    printf("Using password: %s\n", hardcodedPassword);

    // Simulating database operations
    printf("Connected to the database. Performing operations...\n");

    // Simulating database connection close
    printf("Closing the database connection.\n");
}

void generateSecretToken() {
    int secretToken = std::rand();
    // CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    printf("Secret token: %d\n", secretToken);
}

void processMessage(const char* message) {
    char* copy = (char*)malloc((strlen(message) + 1) * sizeof(char));
    strcpy(copy, message);
    if (strlen(copy) > 10) {
        printf("Long message received: %s\n", copy);
        free(copy);
    }
    printf("Processing message: %s\n", copy);
    free(copy);
    // CWE-415: Double Free
}

int main() {
    processUser();
    processQuery();
    processNumber();
    processFile();
    processPassword();
    connectToDatabase();
    generateSecretToken();
    processMessage("Hello, World!");
    return 0;
}