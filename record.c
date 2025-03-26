/*
 * Copyright (c) 2025 <sashan@openssl.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <pthread.h>
#include <assert.h>
#include <inttypes.h>

#include "utils/queue.h"
#include "utils/tree.h"
#include "kelf.h"

#include "mprofile.h"

enum {
	ALLOC = 1,
	FREE = 2,
	REALLOC = 3
};

#define	MPROFILE_REC_ID		"\"id\""
#define	MPROFILE_REC_MEM	"\"addr\""
#define	MPROFILE_REC_REALLOC	"\"realloc\""
#define	MPROFILE_REC_DELTA	"\"delta_sz\""
#define	MPROFILE_REC_STATE	"\"state\""
#define	MPROFILE_REC_STACK_ID	"\"stack_id\""
#define	MPROFILE_REC_NEXT_ID	"\"next_id\""
#define	MPROFILE_REC_PREV_ID	"\"prev_id\""
#define	MPROFILE_TIMESTAMP	"\"time\""
#define	MPROFILE_TIME_S		"\"s\""
#define	MPROFILE_TIME_NS	"\"ns\""
struct mprofile_record {
	uint64_t			 mpr_id;
	void				*mpr_mem;
	void				*mpr_realloc;
					    /* returned by realloc() */
	ssize_t				 mpr_delta;
	char				 mpr_state;
	unsigned int			 mpr_stack_id;
	uint64_t			 mpr_prev_id;
	uint64_t			 mpr_next_id;
	struct timespec			 mpr_ts;
	TAILQ_ENTRY(mprofile_record)	 mpr_tqe;
	/*
	 * note: mpr_rbe is dual purposed. The first we use it
	 * is to sort records by mpr_id when we merge per-thread
	 * instances. On its second use we use it for construction
	 * of allocation chains. Those two processing never happens
	 * simultaneously, therefore we can have just one mpr_rbe.
	 */
	RB_ENTRY(mprofile_record)	 mpr_rbe;
};

struct mprofile {
	TAILQ_HEAD(mp_list, mprofile_record)	 mp_tqhead;
	mprofile_stset_t			*mp_stset;
	TAILQ_ENTRY(mprofile)			 mp_tqe;
};

struct shlib {
	char		*shl_name;
	unsigned long	 shl_base;
};

#define	MAX_SHLIBS	32
static struct shlib shlibs[MAX_SHLIBS];

/* we keep symbols global */
#ifdef	_WITH_STACKTRACE
static struct syms *syms = NULL;
#endif

static uint64_t mpr_id = 0;

static struct timespec start_time_tv;

static pthread_mutex_t mtx;

static TAILQ_HEAD(profiles, mprofile)	profiles;

static mprofile_t *master = NULL;

RB_HEAD(mprofile_record_sort, mprofile_record);

RB_HEAD(mprofile_record_mem, mprofile_record);

static int record_id_compare(struct mprofile_record *,
    struct mprofile_record *);

static int record_mem_compare(struct mprofile_record *,
    struct mprofile_record *);

static struct mprofile_record_sort sorter;

RB_GENERATE_STATIC(mprofile_record_sort, mprofile_record, mpr_rbe,
    record_id_compare);

RB_GENERATE_STATIC(mprofile_record_mem, mprofile_record, mpr_rbe,
    record_mem_compare);


static int 
record_id_compare(struct mprofile_record *a_mpr, struct mprofile_record *b_mpr)
{
	if (a_mpr->mpr_id < b_mpr->mpr_id)
		return (-1);
	else if (a_mpr->mpr_id > b_mpr->mpr_id)
		return (1);
	else
		return (0);
}

static int 
record_mem_compare(struct mprofile_record *a_mpr, struct mprofile_record *b_mpr)
{
	if (a_mpr->mpr_mem < b_mpr->mpr_mem)
		return (-1);
	else if (a_mpr->mpr_mem > b_mpr->mpr_mem)
		return (1);
	else
		return (0);
}

static struct mprofile_record *
create_mprofile_record(void)
{
	struct mprofile_record *mpr;

	mpr = (struct mprofile_record *)malloc(
	    sizeof (struct mprofile_record));
	if (mpr == NULL)
		return (NULL);
	memset(mpr, 0, sizeof (struct mprofile_record));

	clock_gettime(CLOCK_REALTIME, &mpr->mpr_ts);

	return (mpr);
}

static void
print_mprofile_record(FILE *f, struct mprofile_record *mpr)
{
	const char *state;

	switch (mpr->mpr_state) {
	case ALLOC:
		state = "\"allocated\"";
		break;
	case FREE:
		state = "\"free\"";
		break;
	case REALLOC:
		state = "\"realloc\"";
		break;
	default:
		state = "\"???\"";
	}
	fprintf(f, "\t{\n");
	fprintf(f, "\t\t%s : %"PRIu64",\n", MPROFILE_REC_ID, mpr->mpr_id);
	fprintf(f, "\t\t%s : %"PRIu64",\n", MPROFILE_REC_MEM,
	    (unsigned long long)mpr->mpr_mem);
	fprintf(f, "\t\t%s : %"PRIu64",\n", MPROFILE_REC_REALLOC,
	    (unsigned long long)mpr->mpr_realloc);
	fprintf(f, "\t\t%s : %zd,\n", MPROFILE_REC_DELTA, mpr->mpr_delta);
	fprintf(f, "\t\t%s : %s,\n", MPROFILE_REC_STATE, state);
	fprintf(f, "\t\t%s : %"PRIu64",\n", MPROFILE_REC_NEXT_ID,
	    mpr->mpr_next_id);
	fprintf(f, "\t\t%s : %"PRIu64",\n", MPROFILE_REC_PREV_ID,
	    mpr->mpr_prev_id);
	fprintf(f, "\t\t%s : %u,\n", MPROFILE_REC_STACK_ID,
	    mpr->mpr_stack_id);
	fprintf(f, "\t\t%s : {\n", MPROFILE_TIMESTAMP);
	fprintf(f, "\t\t\t%s : %lld,\n", MPROFILE_TIME_S,
	    (long long)mpr->mpr_ts.tv_sec);
	fprintf(f, "\t\t\t%s : %lu\n", MPROFILE_TIME_NS,
	    mpr->mpr_ts.tv_nsec);
	fprintf(f, "\t\t}\n");
}

mprofile_t *
mprofile_create(void)
{
	mprofile_t *mp;

	if (start_time_tv.tv_sec == 0)
		clock_gettime(CLOCK_REALTIME, &start_time_tv);

	mp = (mprofile_t *) malloc(sizeof (mprofile_t));
	if (mp == NULL)
		return (NULL);

	TAILQ_INIT(&mp->mp_tqhead);

#ifdef _WITH_STACKTRACE
	mp->mp_stset = mprofile_create_stset();
#endif

	return (mp);
}

#ifdef _WITH_STACKTRACE
static void
print_trace(unsigned long long frame, void *f_arg)
{
	FILE *f = (FILE *)f_arg;
	char buf[90];

	kelf_snprintsym(syms, buf, sizeof (buf), frame, 0);
	fprintf(f, "\"%s\", ", buf);
}

static void
print_stack(FILE *f, mprofile_stack_t *stack)
{
	fprintf(f, "\t{\n");
	fprintf(f, "\t\t\"id\" : %u,\n", mprofile_get_stack_id(stack));
	fprintf(f, "\t\t\"stack_count\" : %u,\n",
	    mprofile_get_stack_count(stack));
	fprintf(f, "\t\t\"thread_id\" : %"PRIu64",\n",
	    (unsigned long long)mprofile_get_thread_id(stack));
	fprintf(f, "\t\t\"stack_trace\" : [ ");
	mprofile_walk_stack(stack, print_trace, f);
	fprintf(f, "\"\" ]\n");
	fprintf(f, "\t}");
}
#endif

static void
profile_save(FILE *f, mprofile_t *mp)
{
#ifdef	_WITH_STACKTRACE
	mprofile_stack_t *stack;
#endif
	struct mprofile_record *mpr;
	int first = 1;

	if (f == NULL)
		return;
	
	fprintf(f, "{ \"start_time\" : {\n");
	fprintf(f, "\t%s : %lld,\n", MPROFILE_TIME_S,
	    (long long)start_time_tv.tv_sec);
	fprintf(f, "\t%s : %lu\n", MPROFILE_TIME_NS, start_time_tv.tv_nsec);
	fprintf(f, "  },\n");
	fprintf(f, "\t\"annotation\" : \"%s\",\n", mprofile_get_annotation());
	fprintf(f, "  \"allocations\" : [\n");
	TAILQ_FOREACH(mpr, &mp->mp_tqhead, mpr_tqe) {
		if (first == 0)
			fprintf(f, "\t},\n");
		else
			first = 0;
		print_mprofile_record(f, mpr);
	}
	if (first == 0)
		fprintf(f, "\t}\n");
	fprintf(f, "],\n");

#ifdef _WITH_STACKTRACE
	fprintf(f, " \"stacks\" : [\n");
	stack = mprofile_get_next_stack(mp->mp_stset, NULL);
	while (stack != NULL) {
		print_stack(f, stack);
		stack = mprofile_get_next_stack(mp->mp_stset, stack);
		if (stack != NULL)
			fprintf(f, ",\n");
	}
	fprintf(f, "\n]}");
#else
	fprintf(f, " \"stacks\" : [\n");
	fprintf(f, "]}");
#endif
}

void
mprofile_destroy(mprofile_t *mp)
{
	struct mprofile_record *mpr, *walk;

	TAILQ_FOREACH_SAFE(mpr, &mp->mp_tqhead, mpr_tqe, walk) {
		TAILQ_REMOVE(&mp->mp_tqhead, mpr, mpr_tqe);
		free(mpr);
	}
#ifdef _WITH_STACKTRACE
	mprofile_destroy_stset(mp->mp_stset);
#endif
	free(mp);
}

void
mprofile_record_alloc(mprofile_t *mp, void *buf, size_t buf_sz,
    mprofile_stack_t *mps)
{
	struct mprofile_record *mpr;

	mpr = create_mprofile_record();
	if (mpr == NULL) {
		fprintf(stderr, "%s create_mprofile_record() failed\n", __func__);
		return;
	}

	mpr->mpr_mem = buf;
	mpr->mpr_delta = (ssize_t)buf_sz;
	mpr->mpr_state = ALLOC;
	mpr->mpr_id = __atomic_add_fetch(&mpr_id, 1, __ATOMIC_ACQ_REL);
	TAILQ_INSERT_TAIL(&mp->mp_tqhead, mpr, mpr_tqe);

#ifdef _WITH_STACKTRACE
	if (mps != NULL) {
		mps = mprofile_add_stack(mp->mp_stset, mps);
		mpr->mpr_stack_id = mprofile_get_stack_id(mps);
	} else {
		mpr->mpr_stack_id = 0;
	}
#endif
}

void
mprofile_record_free(mprofile_t *mp, void *buf, size_t sz, mprofile_stack_t *mps)
{
	struct mprofile_record *mpr;

	mpr = create_mprofile_record();
	if (mpr == NULL) {
		fprintf(stderr, "%s create_mprofile_record() failed\n", __func__);
		return;
	}

	mpr->mpr_mem = buf;
	mpr->mpr_state = FREE;
	mpr->mpr_delta = sz * -1;
	mpr->mpr_id = __atomic_add_fetch(&mpr_id, 1, __ATOMIC_ACQ_REL);
	TAILQ_INSERT_TAIL(&mp->mp_tqhead, mpr, mpr_tqe);

#ifdef _WITH_STACKTRACE
	if (mps != NULL) {
		mps = mprofile_add_stack(mp->mp_stset, mps);
		mpr->mpr_stack_id = mprofile_get_stack_id(mps);
	} else {
		mpr->mpr_stack_id = 0;
	}
#endif
}

void
mprofile_record_realloc(mprofile_t *mp, void *buf, size_t buf_sz,
    size_t orig_sz, void *old_buf, mprofile_stack_t *mps)
{
	struct mprofile_record *mpr;

	mpr = create_mprofile_record();
	if (mpr == NULL) {
		fprintf(stderr, "%s create_mprofile_record() failed\n", __func__);
		return;
	}

	mpr->mpr_mem = buf;
	mpr->mpr_delta = buf_sz - orig_sz;
	mpr->mpr_realloc = old_buf;
	mpr->mpr_state = REALLOC;
	mpr->mpr_id = __atomic_add_fetch(&mpr_id, 1, __ATOMIC_ACQ_REL);
	TAILQ_INSERT_TAIL(&mp->mp_tqhead, mpr, mpr_tqe);

#ifdef _WITH_STACKTRACE
	if (mps != NULL) {
		mps = mprofile_add_stack(mp->mp_stset, mps);
		mpr->mpr_stack_id = mprofile_get_stack_id(mps);
	} else {
		mpr->mpr_stack_id = 0;
	}
#endif
}

#ifdef	_WITH_STACKTRACE
static void
add_shlib(Dl_info *dli)
{
	unsigned int i = 0;

	while (shlibs[i].shl_name != NULL && i < MAX_SHLIBS) {
		if (strcmp(shlibs[i].shl_name, dli->dli_fname) == 0)
			return;
		i++; }

	if (i == MAX_SHLIBS)
		return;

	shlibs[i].shl_name = strdup(dli->dli_fname);
	shlibs[i].shl_base = (uintptr_t)dli->dli_fbase;
}

static void
walk_stack(unsigned long long frame, void *arg)
{
	Dl_info dli;

	if (dladdr((uintptr_t *)frame, &dli) != 0)
		add_shlib(&dli);
}
#endif

/*
 * This is expensive, we walk trhough all stacks
 * to find list of shared libraries. There must
 * better way to obtain the list of shared libraries.
 */
static void
load_syms(mprofile_t *mp)
{
#ifdef _WITH_STACKTRACE
	unsigned int	i;
	mprofile_stack_t *stack;

	stack = mprofile_get_next_stack(mp->mp_stset, NULL);
	while (stack != NULL) {
		mprofile_walk_stack(stack, walk_stack, NULL);
		stack = mprofile_get_next_stack(mp->mp_stset, stack);
	}

	for (i = 0; i < MAX_SHLIBS; i++) {
		if (shlibs[i].shl_name != NULL)
			syms = kelf_open(shlibs[i].shl_name, syms,
			    shlibs[i].shl_base);
	}
#endif
}

void
mprofile_add(mprofile_t *mp)
{
	pthread_mutex_lock(&mtx);
	TAILQ_INSERT_TAIL(&profiles, mp, mp_tqe);
	pthread_mutex_unlock(&mtx);
}

static void
build_chains(mprofile_t *mp)
{
	struct mprofile_record key_mpr;
	struct mprofile_record *mpr, *tree_mpr;
	struct mprofile_record_mem memtree;

	RB_INIT(&memtree);
	memset(&key_mpr, 0, sizeof (struct mprofile_record));

	TAILQ_FOREACH(mpr, &mp->mp_tqhead, mpr_tqe) {
		switch (mpr->mpr_state) {
		case ALLOC:
			tree_mpr = RB_INSERT(mprofile_record_mem, &memtree,
			    mpr);
			if (tree_mpr != NULL) {
				fprintf(stderr,
				    "%s 0x%p (alloc) already found in "
				    "tree %p %p\n", __func__, mpr->mpr_mem,
				    mpr, tree_mpr);
				abort();
			}
			break;
		case FREE:
			if (mpr->mpr_mem == NULL)
				continue;
			key_mpr.mpr_mem = mpr->mpr_mem;
			tree_mpr = RB_FIND(mprofile_record_mem, &memtree,
			    &key_mpr);
			if (tree_mpr == NULL) {
				fprintf(stderr, "%s %p (free) address was not "
				    "allocated\n", __func__, mpr->mpr_mem);
				abort();
			}
			RB_REMOVE(mprofile_record_mem, &memtree, tree_mpr);
			assert(tree_mpr->mpr_next_id == 0);
			tree_mpr->mpr_next_id = mpr->mpr_id;
			assert(mpr->mpr_prev_id == 0);
			mpr->mpr_prev_id = tree_mpr->mpr_id;
			break;
		case REALLOC:
			key_mpr.mpr_mem = mpr->mpr_realloc;
			tree_mpr = RB_FIND(mprofile_record_mem, &memtree,
			    &key_mpr);
			if (tree_mpr == NULL) {
				fprintf(stderr,
				    "%s %p (realloc) address was not "
				    "allocated\n", __func__, mpr->mpr_mem);
				abort();
			}
			RB_REMOVE(mprofile_record_mem, &memtree, tree_mpr);
			assert(tree_mpr->mpr_next_id == 0);
			tree_mpr->mpr_next_id = mpr->mpr_id;
			assert(mpr->mpr_prev_id == 0);
			mpr->mpr_prev_id = tree_mpr->mpr_id;
			/*
			 * insert realloc record to tree.
			 */
			tree_mpr = RB_INSERT(mprofile_record_mem, &memtree,
			    mpr);
			if (tree_mpr != NULL) {
				fprintf(stderr,
				    "%s 0x%p (realloc) already found in "
				    "tree %p %p\n", __func__, mpr->mpr_mem,
				    mpr, tree_mpr);
				abort();
			}
		}
	}

	/*
	 * tree should be empty, if not then there must be leaks
	 * We don't bother to report those leaks (at least now).
	 */
}

void
mprofile_save(FILE *f, int link_chains)
{
	struct mprofile		*mp, *walk;
#ifdef	_WITH_STACKTRACE
	mprofile_stack_t	*st;
#endif
	struct mprofile_record	*mpr;

	RB_INIT(&sorter);

	TAILQ_FOREACH_SAFE(mp, &profiles, mp_tqe, walk) {
		TAILQ_REMOVE(&profiles, mp, mp_tqe);
		if (master == NULL)
			master = mp;

		while ((mpr = TAILQ_FIRST(&mp->mp_tqhead)) != NULL) {
			TAILQ_REMOVE(&mp->mp_tqhead, mpr, mpr_tqe);
#ifdef	NDEBUG
			RB_INSERT(mprofile_record_sort, &sorter, mpr);
#else
			assert(RB_INSERT(mprofile_record_sort, &sorter,
			    mpr) == NULL);
#endif

#ifdef	_WITH_STACKTRACE
			if (mpr->mpr_stack_id != 0) {
				st = mprofile_merge_stack(
				    master->mp_stset, mp->mp_stset,
				    mpr->mpr_stack_id);
				mpr->mpr_stack_id = mprofile_get_stack_id(st);
			}
#endif
		}

		/*
		 * we want to keep master
		 */
		if (master != mp)
			mprofile_destroy(mp);

	}

	while (!RB_EMPTY(&sorter)) {
		mpr = RB_MIN(mprofile_record_sort, &sorter);
		RB_REMOVE(mprofile_record_sort, &sorter, mpr);
		TAILQ_INSERT_TAIL(&master->mp_tqhead, mpr, mpr_tqe);
	}

	if (link_chains == 1)
		build_chains(master);

	load_syms(master);
	profile_save(f, master);
}

void
mprofile_init(void)
{
	pthread_mutex_init(&mtx, NULL);
	TAILQ_INIT(&profiles);
}

void
mprofile_done(void)
{
	unsigned int	i;

	for (i = 0; i < MAX_SHLIBS; i++)
		free(shlibs[i].shl_name);

#ifdef	_WITH_STACKTRACE
	kelf_close(syms);
#endif

	pthread_mutex_destroy(&mtx);
}

const char *
mprofile_get_annotation(void)
{
	char *annotation = getenv("MPROFILE_ANNOTATION");
	static char annotation_buf[512];
	char *dst, *src;

	if (annotation == NULL)
		return ("FooBar annotation");

	src = annotation;
	annotation_buf[511] = '\0';
	dst = annotation_buf;
	while (*src && dst < &annotation_buf[511]) {
		if (*src == '"') {
			*dst++ = '\\';
			if (dst < &annotation_buf[511])
				*dst++ = *src++;
		} else
			*dst++ = *src++;
	}

	return (annotation_buf);
}
