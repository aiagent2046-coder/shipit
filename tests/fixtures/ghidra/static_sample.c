#include <stdio.h>

int drydock_add(int left, int right) {
    return left + right;
}

int main(void) {
    puts("Drydock static analysis fixture: never executed by the test");
    return drydock_add(2, 3);
}
