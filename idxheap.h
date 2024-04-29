#ifndef IDXHEAP_H
#define IDXHEAP_H

#include <stdint.h>

struct idxheap_item {
	void                *data;
	size_t               index;
	struct idxheap_item *next;
};

struct idxheap {
	struct idxheap_item **h;
	size_t                sz;
	int                   n;

	struct idxheap_item **b;
	size_t                buckets;

	int      (*cmp)(const void *, const void *);
	int      (*match)(const void *, const void *);
	void     (*destroy)(void *);
	uint32_t (*hash)(const void *);
};

int   idxheap_init(struct idxheap *, size_t,
          int (*cmp)(const void *, const void *),
          int (*match)(const void *, const void *),
	  void (*destroy)(void *), uint32_t (*hash)(const void *));
void  idxheap_free(struct idxheap *);
int   idxheap_insert(struct idxheap *, void *);
void *idxheap_peek(struct idxheap *, int);
void *idxheap_lookup(struct idxheap *, const void *);
void *idxheap_update(struct idxheap *, const void *);
void *idxheap_removei(struct idxheap *, int);
void *idxheap_top(struct idxheap *);
void *idxheap_removek(struct idxheap *, void *);

#endif
