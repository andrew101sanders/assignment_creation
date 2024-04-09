#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <random>

void processUser() {
    char userInput[100];
    printf("Enter a username: ");

    //CWE-120 - Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
    scanf("%s", userInput);
}

void processNumber() {
    int number;
    printf("Enter a number: ");
    scanf("%d", &number);
    int array[10];

    // CWE-119 Improper Restriction of Operations within the Bounds of a Memory Buffer
    array[number] = 42;

    // CWE-120: Buffer Overflow
    printf("Number processed: %d\n", number);
}

void processFile() {
    char filename[100];
    printf("Enter a filename: ");

    //CWE-120 - Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
    scanf("%s", filename);
    FILE* file = fopen(filename, "r");
    char buffer[100];

    // CWE-476 NULL Pointer Dereference (Stream pointer might be NULL)
    fgets(buffer, sizeof(buffer), file);
    printf("File content: %s\n", buffer);
    fclose(file);

}

// Hint: There are multiple ways to solve this. Consider the following links:
// https://en.cppreference.com/w/cpp/utility/program/getenv
// https://stackoverflow.com/a/54662065 
void connectToDatabase() {
    const char* hardcodedUsername = "admin";

    // CWE - CWE-798 - Use of Hard-coded Credentials
    // CWE - CWE-259 - Use of Hard-coded Password
    const char* hardcodedPassword = "secret";

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
    // CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    int secretToken = std::rand();
    printf("Secret token: %d\n", secretToken);
}

void processMessage(const char* message) {

    // CWE-120 - Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
    char* copy = (char*)malloc(strlen(message) + 1);

    // CWE-120 - Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
    strcpy(copy, message);

    // CWE-120 - Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
    if (strlen(copy) > 10) {
        printf("Long message received: %s\n", copy);
        free(copy);
    }

    // CWE-416 - Use After Free
    printf("Processing message: %s\n", copy);

    // CWE-415: Double Free
    free(copy);

}

int main() {
    processUser();
    processNumber();
    processFile();
    connectToDatabase();
    generateSecretToken();
    processMessage("Hello, World!");
    return 0;
}