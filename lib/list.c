#include "list.h"
#include <stdlib.h>

// I HAVE REMOVED THE PREVIOUS LIST FUNCTIONS AND REPLACED THEM WITH MY OWN.
// the queue functions have also been slightly altered

list_node* new_node(void* data) {
    list_node* node = (list_node*)malloc(sizeof(list_node));
    if (!node) {
        exit(EXIT_FAILURE);
    }
    node->data = data;
    node->next = NULL;
    return node;
}

list_node* new_list() {
    return NULL;
}

void insert_node(list_node** head, void* data, int pos) {
    list_node* new = new_node(data);

    if (pos <= 0 || *head == NULL) {
        new->next = *head;
        *head = new;
        return;
    }

    list_node* temp = *head;
    for (int i = 0; i < pos - 1 && temp->next != NULL; i++) {
        temp = temp->next;
    }

    new->next = temp->next;
    temp->next = new;
}

void del_node(list_node** head, int pos) {
    if (*head == NULL) return;

    list_node* temp;
    if (pos <= 0) {
        temp = *head;
        *head = (*head)->next;
        free(temp->data);
        free(temp);
        return;
    }

    list_node* prev = *head;
    for (int i = 0; i < pos - 1 && prev->next != NULL; i++) {
        prev = prev->next;
    }

    if (prev->next == NULL) return;

    temp = prev->next;
    prev->next = temp->next;
    free(temp->data);
    free(temp);
}

list_node* get_node(list_node* head, void* data) {
    while (head != NULL) {
        if (head->data == data) {
            return head;
        }
        head = head->next;
    }
    return NULL;
}

int list_len(list_node* head) {
    int count = 0;
    while (head != NULL) {
        count++;
        head = head->next;
    }
    return count;
}

void free_list(list_node* head) {
    list_node* temp;
    while (head != NULL) {
        temp = head;
        head = head->next;
        free(temp->data);
        free(temp);
    }
}