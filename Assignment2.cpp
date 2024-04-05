#include <stdio.h>

int calculateSum(int a, int b) {
    return a + b;
}

int main()
{
    int a, b;
    scanf("%d", &a);
    scanf("%d", &b);
    int n = calculateSum(a, b);
    printf("The sum is %d\n", n);
}