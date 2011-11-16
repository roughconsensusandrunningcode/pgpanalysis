/*
 * Copyright (c) 2004,2005 Matthias Bauer <matthiasb@acm.org>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef NOQUEUE
#include <sys/queue.h>
#include <sys/tree.h>
#else
#include "sys/queue.h"
#include "sys/tree.h"
#endif				/* NOQUEUE */

#include <sys/time.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <search.h>
#include <string.h>
#include <errno.h>

#define COMPFILE "maximal.compound"
#define NUM_ATTRIBS 2

#define VR 0
#define CR 1

extern int      optind;
extern int      optopt;
extern int      opterr;
extern int      optreset;
int             debug = 0;
int             dumpflag = 1;
int             idlen = 16;

LIST_HEAD(listhead, _listelem);
TAILQ_HEAD(tailqhead, _listelem);
RB_HEAD(node_tree, _vertex) nodeshead = RB_INITIALIZER(&nodeshead);
RB_HEAD(sort_tree, _sortelem) sorthead = RB_INITIALIZER(&sorthead);
RB_PROTOTYPE(node_tree, _vertex, nnode, vertcmp);
RB_PROTOTYPE(sort_tree, _sortelem, snode, sortcmp);

struct _listelem {
	/* _listelem can be a member of a LIST xor a TAILQueue */
	LIST_ENTRY(_listelem) sl_elem;
	TAILQ_ENTRY(_listelem) tq_elem;
	struct _vertex *vert;
};

/* RB_TREE for sorting by centrality */
/* XXX Heap would be nicer */
struct _sortelem {
	double          centrality;

	/* Head of a LIST of vertices with this centrality */
	struct listhead *vertices;

	/* _sortelem is a member of a tree for sorting wrt centrality */
	                RB_ENTRY(_sortelem) snode;
};

/*
 * Our main structure to store keys and their relations.
 */
struct _vertex {
	char           *id;
	double          centrality;

	/* Lists of successors and predecessors */
	struct listhead *successors;
	                LIST_ENTRY(_listelem) entries;

	struct listhead *predecessors;
	                LIST_ENTRY(_listelem) pentries;

	/*
	 * _vertex is a member of a tree for lookups by name
	 * and for uniqueness
	 */
	                RB_ENTRY(_vertex) nnode;

	/*
	 * array of pointers to attributes XXX only one (vr_attr) is defined
	 */
	void           *attribs[NUM_ATTRIBS];

	/* "distance" attribute, used in BFS routines a lot */
	double          d;
};

typedef struct _vertex *vertex;

/* vertex attributes used in Brandes' algorithm */
struct vr_attr {
	double          sigma;
	double          delta;
	struct tailqhead *P;
};

struct vr_attr *
vr_alloc(void)
{
	struct vr_attr *new;
	struct tailqhead *p;

	if ((new = (struct vr_attr *) malloc(sizeof(struct vr_attr))) == NULL) {
		fprintf(stderr, "malloc failed\n");
		exit(2);
	}
	if ((p = (struct tailqhead *) malloc(sizeof(struct tailqhead))) == NULL) {
		fprintf(stderr, "malloc failed\n");
		exit(2);
	}
	new->sigma = 0.0;
	new->delta = 0.0;
	TAILQ_INIT(p);
	new->P = p;
	return new;
}

void 
vr_free(struct vr_attr * vr)
{
	struct tailqhead *p;
	if (vr == NULL) {
		return;
	}
	p = vr->P;
	if (p == NULL) {
		free(vr);
		return;
	}
	while (!(TAILQ_EMPTY(p))) {
		TAILQ_REMOVE(p, TAILQ_FIRST(p), tq_elem);
	}
	free(p);
	free(vr);
}

struct _listelem *
list_alloc(void)
{
	struct _listelem *elem;
	if ((elem = (struct _listelem *) malloc(sizeof(struct _listelem))) == NULL) {
		fprintf(stderr, "malloc failed\n");
		exit(2);
	}
	/* Make sure it's fresh */
	bzero((void *) elem, sizeof(struct _listelem));

	return elem;
}

struct _sortelem *
sort_alloc(void)
{
	struct _sortelem *elem;
	struct listhead *h;
	if ((elem = (struct _sortelem *) malloc(sizeof(struct _sortelem))) == NULL) {
		fprintf(stderr, "malloc failed\n");
		exit(2);
	}
	if ((h = (struct listhead *) malloc(sizeof(struct listhead))) == NULL) {
		fprintf(stderr, "malloc failed\n");
		exit(2);
	}
	elem->vertices = h;

	return elem;
}

void 
list_copy(struct listhead * dst_h, struct listhead * src_h)
{
	struct _listelem *s;
	LIST_FOREACH(s, src_h, sl_elem) {
		struct _listelem *d;
		d = list_alloc();
		d->vert = s->vert;
		LIST_INSERT_HEAD(dst_h, d, sl_elem);
	}
	return;
}

void 
list_free(struct listhead * l)
{
	while (!LIST_EMPTY(l)) {
		LIST_REMOVE(LIST_FIRST(l), sl_elem);
	}
	return;
}


void
enqueue(struct tailqhead * tq_h, struct _vertex * v)
{
	struct _listelem *elem;

	elem = list_alloc();
	elem->vert = v;
	TAILQ_INSERT_TAIL(tq_h, elem, tq_elem);
	return;
}

struct _vertex *
dequeue(struct tailqhead * tq_h)
{
	struct _vertex *v;
	struct _listelem *elem;

	if (TAILQ_EMPTY(tq_h)) {
		return NULL;
	}
	elem = TAILQ_FIRST(tq_h);
	TAILQ_REMOVE(tq_h, elem, tq_elem);
	v = elem->vert;
	free(elem);
	return v;
}

void
stack_push(struct listhead * sl_h, struct _vertex * v)
{
	struct _listelem *elem;

	elem = list_alloc();
	elem->vert = v;

	LIST_INSERT_HEAD(sl_h, elem, sl_elem);
	return;
}

struct _vertex *
stack_pop(struct listhead * sl_h)
{
	struct _listelem *elem;
	struct _vertex *v;

	if (LIST_EMPTY(sl_h)) {
		return NULL;
	}
	elem = LIST_FIRST(sl_h);
	v = elem->vert;
	LIST_REMOVE(elem, sl_elem);
	free(elem);
	return v;
}

/* Comparison functions for the two types of trees */

int
vertcmp(struct _vertex * a, struct _vertex * b)
{
	return (memcmp(((vertex) a)->id, ((vertex) b)->id, idlen));
}

int
sortcmp(struct _sortelem * a, struct _sortelem * b)
{
	if (a->centrality == b->centrality) {
		return 0;
	}
	if (a->centrality < b->centrality) {
		return -1;
	} else {
		return 1;
	}
	/* quartum non datur */
}


RB_GENERATE(node_tree, _vertex, nnode, vertcmp);
RB_GENERATE(sort_tree, _sortelem, snode, sortcmp);

vertex
newnode(char *id)
{
	vertex          new;
	struct listhead *shead, *phead;

	if ((new = (vertex) malloc(sizeof(struct _vertex))) == NULL) {
		fprintf(stderr, "no malloc\n");
		exit(1);
	}
	if ((shead = (struct listhead *) malloc(sizeof(struct listhead))) == NULL) {
		fprintf(stderr, "no malloc\n");
		exit(1);
	}
	if ((phead = (struct listhead *) malloc(sizeof(struct listhead))) == NULL) {
		fprintf(stderr, "no malloc\n");
		exit(1);
	}
	LIST_INIT(shead);
	LIST_INIT(phead);
	new->successors = shead;
	new->predecessors = phead;
	new->id = strdup(id);
	new->centrality = 0.0;
	new->d = 0.0;
	return new;
}

/* Adds a successor u to v and a precessor v to u */
void
add_neigh(vertex v, vertex u)
{
	struct _listelem *e, *d, *tmp;
	int jump_flag = 0;
	e = list_alloc();
	d = list_alloc();
	e->vert = u;
	d->vert = v;
	if (debug) {
		fprintf(stderr, "adding successor %s to %s\n", u->id, v->id);
	}
	/* Check if the link is already there */
	LIST_FOREACH(tmp, v->successors, sl_elem) {
		if (bcmp(tmp->vert->id, e->vert->id, idlen) == 0) {
			jump_flag++;
			break;
		}
	}
	if (!jump_flag) {
		LIST_INSERT_HEAD(v->successors, e, sl_elem);
	}
	/* To be on the safe side, check the reverse too */
	jump_flag=0;
	LIST_FOREACH(tmp, u->predecessors, sl_elem) {
		if (bcmp(tmp->vert->id, d->vert->id, idlen) == 0) {
			jump_flag++;
			break;
		}
	}
	if (!jump_flag) {
		LIST_INSERT_HEAD(u->predecessors, d, sl_elem);
	}
	return;
}


/*
 * vertex_round
 * 
 * round-function to be called for each vertex of the graph. updates the
 * centrality of vertices on every shortest path from the given vertex to
 * every other.
 * 
 * Algorithm was presented by Ulrik Brandes in "A Faster Algorithm for
 * Betweennes Centrality" in "Journal of Mathematical Sociology",
 * 25(5):163-177, 2001.
 * 
 * Earlier implementations used a modified Floyd-Warshall, and were way
 * too slow.
 */

void
vertex_round(vertex s, struct node_tree * nhead)
{
	vertex          fnode, v, w;
	int             stack_count = 0;
	int             neighbor_count = 0;

	struct listhead stack_head;
	struct tailqhead q_head;
	struct listhead *h;
	struct _listelem *e;

	LIST_INIT(&stack_head);
	TAILQ_INIT(&q_head);

	/* Reset the per-vertex auxillary variables */
	RB_FOREACH(fnode, node_tree, nhead) {
		vr_free((struct vr_attr *) fnode->attribs[VR]);
		fnode->attribs[VR] = (void *) vr_alloc();
		fnode->d = -1.0;
	}

	((struct vr_attr *) s->attribs[VR])->sigma = 1.0;
	s->d = 0.0;

	enqueue(&q_head, s);

	if (debug) {
		fprintf(stderr, "working on %s: \n ", s->id);
	}
	while ( (v = dequeue(&q_head)) ) {

		stack_push(&stack_head, v);
		stack_count++;

		/* iterate over the neighbors */
		h = v->successors;
		neighbor_count = 0;

		if (debug) {
			fprintf(stderr, "Neighbors of %s: \n", v->id);
		}
		if (!LIST_EMPTY(h)) {
			e = LIST_FIRST(h);
			do {
				w = e->vert;
				neighbor_count++;
				if (debug) {
					fprintf(stderr, "%s,", w->id);
				}
				/* Seen the first time? */
				if (w->d < 0) {
					enqueue(&q_head, w);
					w->d = v->d + 1.0;
				}
				/* On shortest path to w via v? */
				/* XXX_nagging_doubt the right direction? */
				if (w->d == (v->d + 1.0)) {
					((struct vr_attr *) w->attribs[VR])->sigma +=
						((struct vr_attr *) v->attribs[VR])->sigma;
					/* append to list P[w] */
					enqueue(((struct vr_attr *) w->attribs[VR])->P, v);
				}
			} while ((e = LIST_NEXT(e, sl_elem)));
			if (debug) {
				fprintf(stderr, "\n");
			}
		}
		if (debug) {
			fprintf(stderr, "\t%s has %d neighbors\n", v->id, neighbor_count);
		}
	}

	if (debug) {
		fprintf(stderr, "Stackheight %d\n", stack_count);
	}
	while ((w = stack_pop(&stack_head))) {
		vertex          v;

		if (debug) {
			fprintf(stderr, "\tStack %s\n", w->id);
		}
		/* go through P[w] */
		if (!TAILQ_EMPTY(((struct vr_attr *) w->attribs[VR])->P)) {
			while ((v = dequeue(((struct vr_attr *) w->attribs[VR])->P))) {
				double          ftmp;

				if (debug) {
					fprintf(stderr, "\t\tList %s\n", v->id);
				}
				ftmp = ((struct vr_attr *) v->attribs[VR])->delta +
					(((struct vr_attr *) v->attribs[VR])->sigma /
				((struct vr_attr *) w->attribs[VR])->sigma) *
					(1.0 +
					 (((struct vr_attr *) w->attribs[VR])->delta));

				/*
				 * Did something go _terribly_, numerically
				 * wrong?
				 */
				if (isinf(ftmp) || isnan(ftmp)) {
					fprintf(stderr, " %s->delta= %f\t %s->sigma= %f \t %s->sigma=%f \t %s->delta=%f\n",
						v->id,
						((struct vr_attr *) v->attribs[VR])->delta,
						v->id,
						((struct vr_attr *) v->attribs[VR])->sigma,
						w->id,
						((struct vr_attr *) w->attribs[VR])->sigma,
						w->id,
						((struct vr_attr *) w->attribs[VR])->delta);
					/* force core-dump */
					kill(getpid(), SIGSEGV);
				}
				((struct vr_attr *) v->attribs[VR])->delta = ftmp;
			}
		}
		if (w != s) {
			w->centrality += ((struct vr_attr *) w->attribs[VR])->delta;
		}
	}
}

void
usage(void)
{
	fprintf(stderr, "usage: wot [-dm] [-l num] file\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\t-d\tdebuging output on\n");
	fprintf(stderr, "\t-m\tdump the biggest component to %s\n", COMPFILE);
	fprintf(stderr, "\t-l num\tids are num chars long\n");
	exit(1);
}

/*
 * component_round
 *
 * Given a starting vertex s, a copy of the graph as RB_TREE
 * with root nhead, it removes the component containing s from
 * the graph and puts the component's vertices (with
 * successor/predecessor  lists) in a list given as parameter.
 */
int
component_round(vertex s, struct node_tree * nhead, struct listhead * list)
{
	vertex          fnode, v;
	int             count = 0;

	struct tailqhead q_head;
	struct _listelem *e, *n;

	TAILQ_INIT(&q_head);
	RB_FOREACH(fnode, node_tree, nhead) {
		fnode->d = 0;
	}

	s->d = 1.0;

	enqueue(&q_head, s);

	while ((v = dequeue(&q_head))) {
		e = list_alloc();
		e->vert = v;
		LIST_INSERT_HEAD(list, e, sl_elem);
		LIST_FOREACH(n, v->successors, sl_elem) {
			/* been there ? */
			if (n->vert->d != 1.0) {
				n->vert->d = 1.0;
				enqueue(&q_head, n->vert);
				count++;
			}
		}
 /* only check forward. assure that the initial node _is_ in the strong component */
#if 0
		LIST_FOREACH(n, v->predecessors, sl_elem) {
			/* been there ? */
			if (n->vert->d != 1.0) {
				n->vert->d = 1.0;
				enqueue(&q_head, n->vert);
				count++;
			}
		}
#endif /* 0 */
		RB_REMOVE(node_tree, nhead, v);
	}
	return count;
}

/*
 * find the largest connected component in a graph. If dumpflag
 * is set, dump component in file COMPFILE.
 */
int
find_biggest_compound(struct node_tree * allkeys, struct node_tree * result)
{
	int             max = 0;
	int             c;
	struct listhead l, maxlist;
	struct _listelem *e;
	vertex          s;
	FILE           *maxcomp = NULL;

	LIST_INIT(&l);
	LIST_INIT(&maxlist);

	/*
	 * XXX The first component with more than 100000 vertices is
	 * returned.
	 */
		while ((!RB_EMPTY(allkeys)) && max < 100000) {
		int             num;
		/* pick vertex with smallest id */
		s = RB_MIN(node_tree, allkeys);
		/* cut out the component containing s */
		num = component_round(s, allkeys, &l);
		if (num > 100) {
			fprintf(stderr, "Interesting component with %d members containing %s\n", num, s->id);
		}
		if (num > max) {
			max = num;
			fprintf(stderr, "New maximum component (%d nodes)\n", max);
			/* XXX This is inefficient */
			list_free(&maxlist);
			list_copy(&maxlist, &l);
		}
		list_free(&l);
	}
	if (dumpflag) {
		if ((maxcomp = fopen(COMPFILE, "w+")) == NULL) {
			fprintf(stderr, "Could not write to %s\n", COMPFILE);
			exit(1);
		}
	}
	c = 0;
	LIST_FOREACH(e, &maxlist, sl_elem) {
		struct _listelem *el;

		RB_INSERT(node_tree, result, e->vert);
		c++;
		if (dumpflag) {
			fprintf(maxcomp, "p%s\n", e->vert->id);
			LIST_FOREACH(el, e->vert->predecessors, sl_elem) {
				fprintf(maxcomp, "s%s\n", el->vert->id);
			}
		}
	}
	if (dumpflag) {
		fclose(maxcomp);
	}
	fprintf(stderr, "Inserted %d nodes\n", c);
	return max;
}

/* Remove a vertex from the graph */
void 
cutat(struct node_tree * t, vertex cut)
{
	vertex          v;
	struct _listelem *e;
	RB_FOREACH(v, node_tree, t) {
		LIST_FOREACH(e, v->successors, sl_elem) {
			if (e->vert == cut) {
				LIST_REMOVE(e, sl_elem);
			}
		}
		LIST_FOREACH(e, v->predecessors, sl_elem) {
			if (e->vert == cut) {
				LIST_REMOVE(e, sl_elem);
			}
		}
	}
	RB_REMOVE(node_tree, t, cut);
}

int
main(int argc, char **argv)
{
	char           *fname = NULL;
	char            line[20];
	char            cur[17], id[17];
	int             ch = 0;
	int             total = 0;
	int             numkeys = 0;
	int             unknown = 0;
	int             done = 0;
	double          perc, todo;
	int             span, hours, mins, secs;
	struct timeval  tvstart, tvnow, tvdiff;

	vertex          nn, searchnode, s;
	vertex          current = NULL;
	struct _sortelem *ord;
	FILE           *in;
	struct node_tree allkeys;

	RB_INIT(&allkeys);

	while ((ch = getopt(argc, argv, "l:dm")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'm':
			dumpflag = 1;
			break;
		case 'l':
			idlen = (int) strtoul(optarg, NULL, 10);
			break;
		default:
			usage();
			/* not reached */
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		fprintf(stderr, "Please give file to parse\n");
	}
	fname = strdup(argv[0]);
	fprintf(stderr, "fname: %s\n", fname);

	if ((in = fopen(fname, "r")) == NULL) {
		fprintf(stderr, "Error opening %s: %s\n", fname, strerror(errno));
		exit(1);
	}

	/*
	 * We expect a file with sequences of lines:
	 * 
	 * p<keyid> 
	 * s<keyid> 
	 * ... 
	 * p<keyid> 
	 * s<keyid> 
	 * ... 
	 * where lines starting with  'p' introduce a public key
	 * and lines starting with 's' the signatures on the key
	 * 
	 * Upon request from Peter Palfrader: Two runs over the file, first find
	 * all p<key> lines, then the s<key> lines, ignoring those that have
	 * no matching p<key> line.
	 */

	/* dummy struct _vertex. We substitute the id later and call RB_FIND */
	searchnode = newnode("0000000000000000");

	/* first run */
	while (fgets(line, idlen + 2, in)) {
		if (line[0] == 'p') {
			strncpy(cur, line + 1, idlen);
			cur[idlen] = 0;
			searchnode->id = cur;
			if ((current = RB_FIND(node_tree, &allkeys, searchnode)) == NULL) {
				current = newnode(cur);
				RB_INSERT(node_tree, &allkeys, current);
				numkeys++;
			}
		}
	}
	fprintf(stderr, "Read %d keys\n", numkeys);
	rewind(in);

	/* second run */
	while (fgets(line, idlen + 2, in)) {
		if (line[0] == 'p') {
			strncpy(cur, line + 1, idlen);
			cur[idlen] = 0;
			searchnode->id = cur;
			if ((current = RB_FIND(node_tree, &allkeys, searchnode)) == NULL) {
				fprintf(stderr, "Wait a moment!\nWe should have added this (%s) before!\n", cur);
				current = newnode(cur);
				RB_INSERT(node_tree, &allkeys, current);

			}
		} else {
			if (line[0] == 's') {
				strncpy(id, line + 1, idlen);
				/* terminate id with \0 */
				id[idlen] = 0;
				/* Ignore self-sigs */
				if (strcmp(cur, id) == 0)
					continue;

				searchnode->id = id;
				if ((nn = RB_FIND(node_tree, &allkeys, searchnode)) == NULL) {
					unknown++;
					/* skip id's without vertices */
					continue;
				}
				if (current == NULL) {
					fprintf(stderr, "Malformed graphfile\n");
					exit(1);
				}
				add_neigh(nn, current);
			}
		}
	}

	fprintf(stderr, "%d signatures from keys not in the keydumps\n", unknown);
	fprintf(stderr, "Finished parsing %s, starting the algorithm\n", fname);

	if (gettimeofday(&tvstart, NULL) != 0) {
		fprintf(stderr, "Could not get time: %s\n", strerror(errno));
		exit(1);
	}

	total = find_biggest_compound(&allkeys, &nodeshead);

	if (gettimeofday(&tvnow, NULL) != 0) {
		fprintf(stderr, "Could not get time: %s\n", strerror(errno));
		exit(1);
	}

	timersub(&tvnow, &tvstart, &tvdiff);

	fprintf(stderr, "Found %d vertex component in %ld seconds", total,
		tvdiff.tv_sec);

	if (gettimeofday(&tvstart, NULL) != 0) {
		fprintf(stderr, "Could not get time: %s\n", strerror(errno));
		exit(1);
	}

	RB_FOREACH(s, node_tree, &nodeshead) {
		vertex_round(s, &nodeshead);
		done++;
		if ((done % 100) == 1 && done > 1) {
			if (gettimeofday(&tvnow, NULL) != 0) {
				fprintf(stderr, "Could not get time: %s\n", strerror(errno));
				exit(1);
			}
			/* Convoluted machinations to get the ETA */
			span = tvnow.tv_sec - tvstart.tv_sec;
			perc = (double) done;
			perc /= total;
			todo = (((double) span) / perc) - (double) span;
			perc *= 100;

			hours = (int) floor(todo / 3600);
			todo -= (hours * 3600.0);
			mins = (int) floor(todo / 60);
			todo -= (mins * 60.0);
			secs = (int) floor(todo);

			fprintf(stderr, "%d\tof %d done\t( %.3f %%)\t(ETA %dh%02dm%02ds)\n", done, total, perc, hours, mins, secs);
		}
	}

	fprintf(stderr, "Finished computation, sorting by centrality\n");

	RB_FOREACH(s, node_tree, &nodeshead) {
		struct _sortelem *so, *found;
		struct _listelem *e;
		so = sort_alloc();
		e = list_alloc();
		so->centrality = s->centrality;
		e->vert = s;
		/* Already got a vertex with same centrality? */
		if ((found = RB_INSERT(sort_tree, &sorthead, so)) != NULL) {
			LIST_INSERT_HEAD(found->vertices, e, sl_elem);
		} else {
			/* First vertex with this centrality */
			LIST_INIT(so->vertices);
			LIST_INSERT_HEAD(so->vertices, e, sl_elem);
		}
	}

	/* print list sorted by centrality  */
	RB_FOREACH(ord, sort_tree, &sorthead) {
		struct _listelem *e;
		LIST_FOREACH(e, ord->vertices, sl_elem) {
			printf("%s;%.9f\n", e->vert->id, ord->centrality);
		}
	}

	fclose(in);

	return 0;
}
