#include <stdio.h>

int calculateSum(int a, int b) {
    return a + b;
}

int main()
{
    int n = calculateSum(0xfffffff0, 0xf);
    printf("The sum is %d\n", n);
}