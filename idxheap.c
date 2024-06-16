#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include "idxheap.h"

static void                 idxheap_swap(struct idxheap *, int, int);
static struct idxheap_item *idxheap_remove_key_internal(struct idxheap *,
                                void *);
static int                  idxheap_heapfix(struct idxheap *, int);
static struct idxheap_item *idxheap_remove_internal(struct idxheap *, int);
static struct idxheap_item *idxheap_lookup_internal(struct idxheap *,
                                const void *, int);

static void
idxheap_swap(struct idxheap *ih, int i, int j)
{
	struct idxheap_item *tmp;

	tmp = ih->h[i];
	ih->h[i] = ih->h[j];
	ih->h[j] = tmp;
	ih->h[i]->index = i;
	ih->h[j]->index = j;
}

static int
idxheap_heapfix(struct idxheap *ih, int i)
{
	int right, left, move, parent;

	if (i > 0) {
		for (parent = (i - 1) / 2;
		    i > 0 && ih->cmp(ih->h[parent]->data, ih->h[i]->data) < 0;
		    i = parent, parent = (i - 1) / 2) {
			idxheap_swap(ih, parent, i);
		}
	}

	for (;;) {
		/* Left child */
		left = i * 2 + 1;
		if (left < ih->n && ih->cmp(ih->h[left]->data,
		    ih->h[i]->data) > 0)
			move = left;
		else
			move = i;

		/* Right child */
		right = i * 2 + 2;
		if (right < ih->n && ih->cmp(ih->h[right]->data,
		    ih->h[move]->data) > 0)
			move = right;

		if (move == i)
			break;

		idxheap_swap(ih, i, move);
		i = move;
	}
	return i;
}

static struct idxheap_item *
idxheap_remove_internal(struct idxheap *ih, int i)
{
	struct idxheap_item *item;

	if (i >= ih->n) {
		errno = ERANGE;
		return NULL;
	}
	item = ih->h[i];

	ih->n--;
	ih->h[i] = ih->h[ih->n];
	ih->h[i]->index = i;

	idxheap_heapfix(ih, i);

	return item;
}

static struct idxheap_item *
idxheap_remove_key_internal(struct idxheap *ih, void *key)
{
	size_t               bucket = ih->hash(key) % ih->buckets;
	struct idxheap_item *p, *prev;

	for (p = ih->b[bucket], prev = NULL;
	    p != NULL;
	    prev = p, p = p->next) {
		 if (!ih->match(p->data, key))
			 continue;

		 if (prev == NULL)
			 ih->b[bucket] = p->next;
		 else
			 prev->next = p->next;
		 return p;
	}
	return NULL;
}

int
idxheap_init(struct idxheap *ih, size_t sz,
    int (*cmp)(const void *, const void *),
    int (*match)(const void *, const void *),
    void (*destroy)(void *), uint32_t (*hash)(const void *))
{
	if (cmp == NULL || match == NULL || hash == NULL) {
		errno = EINVAL;
		return -1;
	}

	if ((ih->h = malloc(sizeof(struct idxheap_item *) * sz)) == NULL)
		return -1;
	ih->sz = sz;
	ih->n = 0;

	if ((ih->b = malloc(sizeof(struct idxheap_item *) * sz)) == NULL) {
		free(ih->h);
		return -1;
	}
	bzero(ih->b, sizeof(void *) * sz);
	ih->buckets = sz;

	ih->cmp = cmp;
	ih->match = match;
	ih->destroy = destroy;
	ih->hash = hash;
	return 0;
}

void
idxheap_free(struct idxheap *ih)
{
	int i;

	if (ih->destroy == NULL)
		return;

	for (i = 0; i < ih->n; i++) {
		ih->destroy(ih->h[i]->data);
		free(ih->h[i]);
	}
	free(ih->h);
	free(ih->b);
}

int
idxheap_insert(struct idxheap *ih, void *data)
{
	int                   parent, i;
	size_t                bucket = ih->hash(data) % ih->buckets;
	struct idxheap_item **resized;
	struct idxheap_item  *item;

	if (ih->n + 1 > ih->sz) {
		if ((resized = realloc(ih->h,
		    sizeof(struct idxheap_item *) * (ih->sz * 2))) == NULL)
			return -1;
		ih->h = resized;
		ih->sz *= 2;
	}

	if ((item = malloc(sizeof(struct idxheap_item))) == NULL)
		return -1;
	item->next = NULL;
	item->data = data;
	item->index = ih->n;

	ih->h[ih->n] = item;

	for (i = ih->n, parent = (i - 1) / 2;
	    i > 0 && ih->cmp(ih->h[parent]->data, ih->h[i]->data) < 0;
	    i = parent, parent = (i - 1) / 2) {
		idxheap_swap(ih, parent, i);
	}
	ih->n++;

	item->next = ih->b[bucket];
	ih->b[bucket] = item;

	return i;
}

void *
idxheap_peek(struct idxheap *ih, int i)
{
	if (i >= ih->n) {
		errno = ERANGE;
		return NULL;
	}
	return ih->h[i]->data;
}

static struct idxheap_item *
idxheap_lookup_internal(struct idxheap *ih, const void *key, int heapfix)
{
	struct idxheap_item *p;

	for (p = ih->b[ih->hash(key) % ih->buckets]; p != NULL; p = p->next) {
		 if (ih->match(p->data, key)) {
			 if (heapfix) {
				 idxheap_heapfix(ih, p->index);
			 }
			 return p;
		 }
	}
	return NULL;
}

void *
idxheap_lookup(struct idxheap *ih, const void *key)
{
	struct idxheap_item *p = idxheap_lookup_internal(ih, key, 0);
	return (p == NULL) ? NULL : p->data;
}

void *
idxheap_update(struct idxheap *ih, const void *key)
{
	struct idxheap_item *p = idxheap_lookup_internal(ih, key, 1);
	return (p == NULL) ? NULL : p->data;
}

void *
idxheap_removei(struct idxheap *ih, int i)
{
	void                *data;
	struct idxheap_item *item = idxheap_remove_internal(ih, i);

	if (item == NULL)
		return NULL;

	if (idxheap_remove_key_internal(ih, item->data) != item)
		abort();
	data = item->data;
	free(item);
	return data;
}

void *
idxheap_top(struct idxheap *ih)
{
	return idxheap_removei(ih, 0);
}

void *
idxheap_removek(struct idxheap *ih, void *key)
{
	void                *data;
	struct idxheap_item *item = idxheap_remove_key_internal(ih, key);

	if (item == NULL)
		return NULL;

	if (idxheap_remove_internal(ih, item->index) != item)
		abort();
	data = item->data;
	free(item);
	return data;
}
