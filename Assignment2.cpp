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
    std::hash<std::string> hasher; //MD5
    size_t hashedPassword = hasher(password);
    // CWE-759: Use of a One-Way Hash without a Salt
    printf("Hashed password: %zu\n", hashedPassword);
}

// Hint: There are multiple ways to solve this. Consider the following links:
// https://en.cppreference.com/w/cpp/utility/program/getenv
// https://stackoverflow.com/a/54662065 
void connectToDatabase() {
    const char* hardcodedUsername = "admin";
    const char* hardcodedPassword = "secret";
    // CWE - CWE-798 - Use of Hard-coded Credentials
    // CWE - CWE-259 - Use of Hard-coded Password

    // Simulating a database connection
    printf("Connecting to the database using username and password...\n");
    printf("Using username: %s\n", hardcodedUsername); // This is fine for the purpose of the assignment.
    printf("Using password: %s\n", hardcodedPassword); // This is fine for the purpose of the assignment.

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
    processNumber();
    processFile();
    processPassword();
    connectToDatabase();
    generateSecretToken();
    processMessage("Hello, World!");
    return 0;
}