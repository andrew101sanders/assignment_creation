#include <iostream>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>

void processUser(char* input) {
    char command[100];
    sprintf(command, "echo 'Processing user: %s'", input);  // CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    system(command);
}

void processQuery(char* query) {
    char sql[200];
    sprintf(sql, "SELECT * FROM users WHERE username = '%s'", query);  // CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    printf("Executing SQL: %s\n", sql);
}

void processNumber(int number) {
    int array[10];
    array[number] = 42;  // CWE-120: Buffer Overflow
    printf("Number processed: %d\n", number);
}

int main() {
    char userInput[100];
    printf("Enter a username: ");
    fgets(userInput, sizeof(userInput), stdin);
    userInput[strcspn(userInput, "\n")] = '\0';  // Remove trailing newline
    processUser(userInput);

    char query[100];
    printf("Enter a query: ");
    fgets(query, sizeof(query), stdin);
    query[strcspn(query, "\n")] = '\0';  // Remove trailing newline
    processQuery(query);

    int number;
    printf("Enter a number: ");
    scanf("%d", &number);
    processNumber(number);

    return 0;
}