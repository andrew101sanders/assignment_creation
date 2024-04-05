#include <iostream>
#include <string>
#include <cstring>
#include <stdlib.h>

using namespace std;

void processUser(string input) {
    string command = "echo 'Processing user: " + input + "'";
    system(command.c_str());  // CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
}

void processQuery(string query) {
    string sql = "SELECT * FROM users WHERE username = '" + query + "'";
    // CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    cout << "Executing SQL: " << sql << endl;
}

void processNumber(int number) {
    int array[10];
    array[number] = 42;  // CWE-120: Buffer Overflow
    cout << "Number processed: " << number << endl;
}

int main() {
    string userInput;
    cout << "Enter a username: ";
    getline(cin, userInput);
    processUser(userInput);

    string query;
    cout << "Enter a query: ";
    getline(cin, query);
    processQuery(query);

    int number;
    cout << "Enter a number: ";
    cin >> number;
    processNumber(number);

    return 0;
}