#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <random>

// 1. Explain the vulnerability/vulnerabilities in the following function and how it can be exploited.
/* Put answer in following space:



*/
// 1.a. Adjust the existing code to mitigate the vulnerabilities.
void processUser() {
    char userInput[100];
    printf("Enter a username: ");

    // CWE-120 - Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
    scanf("%s", userInput);

    printf("Username entered: %s\n", userInput);
}

// 2. Explain the vulnerability/vulnerabilities in the following function and how it can be exploited.
/* Put answer in following space:



*/
// 2.a. Adjust the existing code to mitigate the vulnerabilities.
void processNumber() {
    int number;
    printf("Enter a number: ");

    // Assume a number is entered.
    scanf("%d", &number);
    int array[10];

    // CWE-119 Improper Restriction of Operations within the Bounds of a Memory Buffer
    array[number] = 42;

    // CWE-120: Buffer Overflow
    printf("Number processed: %d\n", number);
}

// 3. Explain the vulnerability/vulnerabilities in the following function and how it can be exploited.
/* Put answer in following space:



*/
// 3.a. Adjust the existing code to mitigate the vulnerabilities.
void processFile() {
    char filename[100];
    printf("Enter a filename: ");

    // CWE-120 - Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
    scanf("%s", filename);
    FILE* file = fopen(filename, "r");
    char buffer[100];

    // CWE-476 NULL Pointer Dereference (Stream pointer might be NULL)
    fgets(buffer, sizeof(buffer), file);
    printf("File content: %s\n", buffer);
    fclose(file);

}

// 4. Explain the vulnerability/vulnerabilities in the following function and how it can be exploited.
/* Put answer in following space:



*/
// 4.a. Adjust the existing code to mitigate the vulnerabilities.
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

// 5. Explain the vulnerability/vulnerabilities in the following function and how it can be exploited.
/* Put answer in following space:



*/
// 5.a. Adjust the existing code to mitigate the vulnerabilities.
// Hint: How secure is std::rand() for cryptography?
void generateSecretToken() {
    // CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    int secretToken = std::rand();
    printf("Secret token: %d\n", secretToken);
}

// 6. Explain the vulnerability/vulnerabilities in the following function and how it can be exploited.
/* Put answer in following space:



*/
// 6.a. Adjust the existing code to mitigate the vulnerabilities.
void processAndCopyMessage() {
    char message[30];
    printf("Enter a message to copy and process: ");

    // CWE-120 - Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
    scanf("%s", message);

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
    processAndCopyMessage();
    return 0;
}