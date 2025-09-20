#ifndef _LIST_H_
#define _LIST_H_

#include <stdio.h>
#include <stdlib.h>

typedef struct list_node {
  void  *data;
  struct list_node *next;
} list_node;

list_node* new_node(void* data);
list_node* new_list();

void insert_node(list_node** head, void* data, int pos);
void del_node(list_node** head, int pos);
list_node* get_node(list_node* head, void* data);
int list_len(list_node* head);
void free_list(list_node* head);

#endif /* _LIST_H_ */