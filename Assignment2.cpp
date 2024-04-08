#include <iostream>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>

void processUser() {
    char userInput[100];
    printf("Enter a username: ");
    fgets(userInput, sizeof(userInput), stdin);
    userInput[strcspn(userInput, "\n")] = '\0';  // Remove trailing newline

    char command[100];
    sprintf(command, "echo 'Processing user: %s'", userInput);  // CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    system(command);
}

void processQuery() {
    char query[100];
    printf("Enter a query: ");
    fgets(query, sizeof(query), stdin);
    query[strcspn(query, "\n")] = '\0';  // Remove trailing newline

    char sql[200];
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
    char data[100];
    printf("Enter some data: ");
    fgets(data, sizeof(data), stdin);
    data[strcspn(data, "\n")] = '\0';  // Remove trailing newline

    char* sanitizedData = strdup(data);  // CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    printf("Sanitized data: %s\n", sanitizedData);
    free(sanitizedData);
}

int main() {
    processUser();
    processQuery();
    processNumber();
    processFile();
    processData();

    return 0;
}