#include "list.h"
#include "my_libc.h"

list_t * list_alloc(void) {
	list_t *list;

	list = (list_t *)malloc(sizeof(list_t));
	if (!list)
		return NULL;
	memset(list, 0, sizeof(list_t));
	list->head = NULL;
	list->count = 0;

	return list;
}

void list_free(list_t *list) {
	list_node_t *node;
	list_node_t *tmp;

	if (!list)
		return;

	node = list->head;
	while (node) {
		tmp = node;
		node = node->next;
		free(tmp);
	}

	free(list);
}

list_node_t * list_append(list_t *list, void *value) {
	list_node_t *new_node;
	list_node_t *node;

	if (!list)
		return NULL;

	new_node = (list_node_t *)malloc(sizeof(list_node_t));
	if (!new_node)
		return NULL;
	new_node->value = value;
	new_node->next = NULL;

	node = list->head;
	if (!node)
		list->head = new_node;
	else {
		while (node) {
			if (!node->next) {
				node->next = new_node;
				break;
			}
			node = node->next;
		}
	}
	list->count++;

	return node;
}

list_node_t * list_head(list_t *list) {
	if (!list)
		return NULL;

	return list->head;
}

size_t list_count(list_t *list) {
	if (!list)
		return 0;

	return list->count;
}

list_node_t * list_next(list_node_t *node) {
	if (!node)
		return NULL;

	return node->next;
}

void * list_get(list_node_t *node) {
	if (!node)
		return NULL;

	return node->value;
}
