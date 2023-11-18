#include <stdio.h>
#include <stdlib.h>

typedef struct s_node {
    int data;
    struct s_node *head;
    struct s_node *next;
} t_node;

int fun7(t_node *n1, long n)
{
    int ret;

    if (n1 == NULL) {
        ret = -1;
    }
    else if (n < n1->data) {
        ret = fun7(n1->head, n); // n1 seems to be some kind of linked data struct
        ret = ret * 2;
    }
    else if (n == n1->data) {
        ret = 0;
    }
    else {
        ret = fun7(n1->next, n);
        ret = ret * 2 + 1;
    }
    return ret;
}

t_node n41 = { .data = 1, .head = NULL, .next = NULL };
t_node n42 = { .data = 7, .head = NULL, .next = NULL };
t_node n43 = { .data = 20, .head = NULL, .next = NULL };
t_node n44 = { .data = 35, .head = NULL, .next = NULL };
t_node n45 = { .data = 40, .head = NULL, .next = NULL };
t_node n46 = { .data = 47, .head = NULL, .next = NULL };
t_node n47 = { .data = 99, .head = NULL, .next = NULL };
t_node n48 = { .data = 1001, .head = NULL, .next = NULL };

t_node n31 = { .data = 6, .head = &n41, .next = &n42 };
t_node n32 = { .data = 22, .head = &n43, .next = &n44 };
t_node n33 = { .data = 45, .head = &n45, .next = &n46 };
t_node n34 = { .data = 107, .head = &n47, .next = &n48 };

t_node n21 = { .data = 8, .head = &n31, .next = &n32 };
t_node n22 = { .data = 50, .head = &n33, .next = &n34 };
t_node n1 = { .data = 36, .head = &n21, .next = &n22 };

int main(void)
{
    for (long n = -1; n < 1002; n++) {
        int ret = fun7(&n1, n);
        if (ret == 7) {
            printf("[+] correct solution: %ld\n", n);
            break;
        }
    }
    return (0);
}