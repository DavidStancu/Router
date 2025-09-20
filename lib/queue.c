#include "queue.h"
#include "list.h"
#include <stdlib.h>
#include <assert.h>

// queue functions have been retouched to make use of the new list functions

struct queue
{
	list_node* head;
	list_node* tail;
	int size;
};

queue create_queue(void)
{
	queue q = malloc(sizeof(struct queue));
	q->head = q->tail = NULL;
	q->size = 0;
	return q;
}

int queue_empty(queue q)
{
	return q->head == NULL;
}

void queue_enq(queue q, void *element)
{
	list_node* new = new_node(element);

    if (queue_empty(q)) {
        q->head = q->tail = new;
    } else {
        q->tail->next = new;
        q->tail = new;
    }
	q->size++;
}

void *queue_deq(queue q)
{
	assert(!queue_empty(q));

    void* data = q->head->data;
    list_node* temp = q->head;

    q->head = q->head->next;

    free(temp);

    if (q->head == NULL) {
        q->tail = NULL;
    }
	
	q->size--;
    return data;
}

int queue_len(queue q)
{
	return q->size;
}