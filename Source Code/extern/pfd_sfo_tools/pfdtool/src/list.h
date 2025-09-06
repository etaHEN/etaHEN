#ifndef _LIST_H_
#define _LIST_H_

#include "types.h"

typedef struct list_node_s {
	void *value;
	struct list_node_s *next;
} list_node_t;

typedef struct list_s {
	list_node_t *head;
	size_t count;
} list_t;

list_t * list_alloc(void);
void list_free(list_t *list);

list_node_t * list_append(list_t *list, void *value);

list_node_t * list_head(list_t *list);
size_t list_count(list_t *list);

list_node_t * list_next(list_node_t *node);
void * list_get(list_node_t *node);

#endif /* !_LIST_H_ */
