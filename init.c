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
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <inttypes.h>

#include <openssl/crypto.h>

#include "mprofile.h"

static void *mp_CRYPTO_malloc_stats(unsigned long, const char *, int);
static void mp_CRYPTO_free_stats(void *, const char *, int);
static void *mp_CRYPTO_realloc_stats(void *, unsigned long, const char *, int);

static void *mp_CRYPTO_malloc_trace(unsigned long, const char *, int);
static void mp_CRYPTO_free_trace(void *, const char *, int);
static void *mp_CRYPTO_realloc_trace(void *, unsigned long, const char *, int);

#ifdef _WITH_STACKTRACE
static void *mp_CRYPTO_malloc_trace_with_stack(unsigned long, const char *, int);
static void mp_CRYPTO_free_trace_with_stack(void *, const char *, int);
static void *mp_CRYPTO_realloc_trace_with_stack(void *, unsigned long, const char *, int);
#endif

struct memhdr {
	size_t		mh_size;
	uint64_t	mh_chk;
};

#define	MS_TOTAL_ALLOCATED	"\"total_allocated_sz\""
#define	MS_TOTAL_RELEASED	"\"total_released_sz\""
#define	MS_ALLOCS		"\"allocs\""
#define	MS_RELEASES		"\"releases\""
#define	MS_REALLOCS		"\"reallocs\""
#define	MS_MAX			"\"max\""
#define	MS_TSTART		"\"tstart\""
#define	MS_TFINISH		"\"tfinish\""
#define	MS_SEC			"\"sec\""
#define	MS_NSEC			"\"nsec\""
static struct memstats {
	uint64_t	ms_total_allocated;
	uint64_t	ms_total_released;
	uint64_t	ms_reallocs;
	uint64_t	ms_allocs;
	uint64_t	ms_free;
	uint64_t	ms_max;
	uint64_t	ms_current;
	struct timespec	ms_start;
	struct timespec	ms_finish;
} ms;

static pthread_key_t mp_pthrd_key;

static char *output_file_name;

static void __attribute__ ((constructor)) init(void);

/* ARGSUSED */
static void
merge_profile(void *void_mprof)
{
	/* profiles are freed in save_profile() on behalf of atexit() */
	pthread_setspecific(mp_pthrd_key, NULL);
}

static void
save_stats(void)
{
	FILE *out_file;

	clock_gettime(CLOCK_REALTIME, &ms.ms_finish);

	out_file = fopen(output_file_name, "w");
	if (out_file == NULL)
		return;

	fprintf(out_file, "{\n");
	fprintf(out_file, "\t\"annotation\" : \"%s\",\n",
	    mprofile_get_annotation());
	fprintf(out_file, "\t%s : %"PRIu64",\n", MS_TOTAL_ALLOCATED,
	    ms.ms_total_allocated);
	fprintf(out_file, "\t%s : %"PRIu64",\n", MS_TOTAL_RELEASED,
	    ms.ms_total_released);
	fprintf(out_file, "\t%s : %"PRIu64",\n", MS_ALLOCS, ms.ms_allocs);
	fprintf(out_file, "\t%s : %"PRIu64",\n", MS_RELEASES, ms.ms_free);
	fprintf(out_file, "\t%s : %"PRIu64",\n", MS_REALLOCS, ms.ms_reallocs);
	fprintf(out_file, "\t%s : %"PRIu64",\n", MS_MAX, ms.ms_max);
	fprintf(out_file, "\t%s : {\n", MS_TSTART);
	fprintf(out_file, "\t\t%s : %"PRIu64",\n", MS_SEC, ms.ms_start.tv_sec);
	fprintf(out_file, "\t\t%s : %ld,\n", MS_NSEC, ms.ms_start.tv_nsec);
	fprintf(out_file, "\t},\n");
	fprintf(out_file, "\t%s : {\n", MS_TFINISH);
	fprintf(out_file, "\t\t%s : %"PRIu64",\n", MS_SEC, ms.ms_finish.tv_sec);
	fprintf(out_file, "\t\t%s : %ld,\n", MS_NSEC, ms.ms_finish.tv_nsec);
	fprintf(out_file, "\t}\n");
	fprintf(out_file, "}");

	fclose(out_file);
}

static void
save_profile_trace(void)
{
	FILE *out_file;

	out_file = fopen(output_file_name, "w");
	if (out_file == NULL)
		return;

	pthread_key_delete(mp_pthrd_key);
	/* don't link alloc (free, realloc) ops to chains */
	mprofile_save(out_file, 0);
	mprofile_done();

	fclose(out_file);
}

static void
save_profile_trace_link_chains(void)
{
	FILE *out_file;

	out_file = fopen(output_file_name, "w");
	if (out_file == NULL)
		return;

	pthread_key_delete(mp_pthrd_key);
	/* link alloc (free, realloc) ops to chains */
	mprofile_save(out_file, 1);
	mprofile_done();

	fclose(out_file);
}

static mprofile_t *
get_mprofile(void)
{
	mprofile_t *mp = (mprofile_t *)pthread_getspecific(mp_pthrd_key);

	if (mp == NULL) {
		mp = mprofile_create();
		/*
		 * My original plan was to call mprofile_add() from
		 * merge_profile() which is a destructor associated with
		 * pthread key to thread specific data. However it did
		 * not work. I was always losing few records.
		 *
		 * I suspect there is something not quite right at libc on
		 * OpenBSD. It looks like thread specific storage associated
		 * with key silently changes/leaks with the first call to
		 * pthread_create(). The first allocations were happening
		 * before pthread_create() got called.
		 *
		 * As a workaround we just add mprofile to list of profiles
		 * when it is created for thread.
		 */
		mprofile_add(mp);
		pthread_setspecific(mp_pthrd_key, mp);
	}

	return (mp);
}

static void
init_stats(void)
{
	clock_gettime(CLOCK_REALTIME, &ms.ms_start);
	CRYPTO_set_mem_functions(mp_CRYPTO_malloc_stats,
	    mp_CRYPTO_realloc_stats,
	    mp_CRYPTO_free_stats);
	atexit(save_stats);
}

/*
 * We use atexit() for consistency with _with_stacks variant.
 */
static void
init_trace(void)
{
	mprofile_init();
	pthread_key_create(&mp_pthrd_key, merge_profile);
	CRYPTO_set_mem_functions(mp_CRYPTO_malloc_trace,
	    mp_CRYPTO_realloc_trace, mp_CRYPTO_free_trace);
	atexit(save_profile_trace);
}

static void
init_trace_with_chains(void)
{
	mprofile_init();
	pthread_key_create(&mp_pthrd_key, merge_profile);
	CRYPTO_set_mem_functions(mp_CRYPTO_malloc_trace,
	    mp_CRYPTO_realloc_trace, mp_CRYPTO_free_trace);
	atexit(save_profile_trace_link_chains);
}

#ifdef _WITH_STACKTRACE
/*
 * We need to use at exit (instead of library destructor), so all shared
 * libraries are still loaded, so we will be able to resolve symbols.
 */
static void
init_trace_with_stacks(void)
{
	mprofile_init();
	pthread_key_create(&mp_pthrd_key, merge_profile);
	CRYPTO_set_mem_functions(mp_CRYPTO_malloc_trace_with_stack,
	    mp_CRYPTO_realloc_trace_with_stack,
	    mp_CRYPTO_free_trace_with_stack);
	atexit(save_profile_trace);
}

static void
init_trace_with_stacks_with_chains(void)
{
	mprofile_init();
	pthread_key_create(&mp_pthrd_key, merge_profile);
	CRYPTO_set_mem_functions(mp_CRYPTO_malloc_trace_with_stack,
	    mp_CRYPTO_realloc_trace_with_stack,
	    mp_CRYPTO_free_trace_with_stack);
	atexit(save_profile_trace_link_chains);
}

#endif

void
mprofile_start(void)
{
	char *mprofile_mode = getenv("MPROFILE_MODE");
	char  default_mode[2] = { '1', 0 };

	if (mprofile_mode == NULL)
		mprofile_mode = default_mode;

	output_file_name = getenv("MPROFILE_OUTF");
	if (output_file_name == NULL)
		return;

	switch (*mprofile_mode) {
	case '1':
		init_stats();
		break;
	case '2':
		init_trace();
		break;
#ifdef _WITH_STACKTRACE
	case '3':
		init_trace_with_stacks();
		break;
#endif
	case '4':
		init_trace_with_chains();
		break;
#ifdef _WITH_STACKTRACE
	case '5':
		init_trace_with_stacks_with_chains();
		break;
#endif
	default:
		init_stats();
	}
}

static void
init(void)
{
	mprofile_start();
}

static void
update_alloc(uint64_t delta)
{
	uint64_t	current, max;

	current = __atomic_add_fetch(&ms.ms_current, delta, __ATOMIC_ACQ_REL);
	max = __atomic_load_n(&ms.ms_max, __ATOMIC_ACQUIRE);
	while (current > max)
		__atomic_compare_exchange_n(&ms.ms_max, &max, current,
		    0 /* want strong */, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE);
}

static void
update_release(uint64_t delta)
{
	__atomic_sub_fetch(&ms.ms_current, delta, __ATOMIC_ACQ_REL);
}

static void *
mp_CRYPTO_malloc_stats(unsigned long sz, const char *f, int l)
{
	struct memhdr *mh;
	void *rv;

	mh = (struct memhdr *) malloc(sz + sizeof (struct memhdr));
	if (mh != NULL) {
		mh->mh_size = sz;
		mh->mh_chk = (uint64_t)mh ^ sz;
		rv = (void *)((char *)mh + sizeof (struct memhdr));
	} else {
		rv = NULL;
	}

	if (mh != NULL) {
		/* RELAXED should be OK as we don't care about result here */
		__atomic_add_fetch(&ms.ms_allocs, 1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&ms.ms_total_allocated, sz,
		    __ATOMIC_RELAXED);
		update_alloc(sz);
	}

	return (rv);
}

static void
mp_CRYPTO_free_stats(void *b, const char *f, int l)
{
	struct memhdr *mh = NULL;
	uint64_t chk;

	if (b != NULL) {
		mh = (struct memhdr *)((char *)b - sizeof (struct memhdr));
		chk = (uint64_t)mh ^ mh->mh_size;
		if (chk != mh->mh_chk) {
			fprintf(stderr, "%p memory corruption detected in %s!",
			    b, __func__);
			abort();
		}
		/* RELAXED should be OK as we don't care about result here */
		__atomic_add_fetch(&ms.ms_free, 1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&ms.ms_total_released, mh->mh_size,
		    __ATOMIC_RELAXED);
		update_release(mh->mh_size);
	}

	free(mh);
}

static void *
mp_CRYPTO_realloc_stats(void *b, unsigned long sz, const char *f, int l)
{
	struct memhdr *mh;
	struct memhdr save_mh;
	uint64_t chk, delta;
	void *rv = NULL;

	if (b != NULL) {
		mh = (struct memhdr *)((char *)b - sizeof (struct memhdr));
		chk = (uint64_t)mh ^ mh->mh_size;
		if (chk != mh->mh_chk) {
			fprintf(stderr, "%p memory corruption detected in %s!",
			    b, __func__);
			abort();
		}
		save_mh = *mh;
	} else {
		mh = NULL;
	}

	if ((sz == 0) && (b != NULL)) {
		/* this is realloc(x, 0); it's counted as free() */

		/* RELAXED should be OK as we don't care about result here */
		__atomic_add_fetch(&ms.ms_free, 1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&ms.ms_total_released, mh->mh_size,
		    __ATOMIC_RELAXED);
		update_release(mh->mh_size);
	}

	mh = (struct memhdr *)realloc(mh, (sz != 0) ?
	    sz + sizeof (struct memhdr) : 0);
	if (mh == NULL)
		return (NULL);	/* consider recording failure */

	if (sz == 0)
		return ((mh == NULL) ?
		    NULL : ((char *)mh) + sizeof (struct memhdr));

	rv = (void *)((char *)mh + sizeof (struct memhdr));
	if (mh != NULL) {
		mh->mh_size = sz;
		mh->mh_chk = (uint64_t)mh ^ sz;
		if (b == NULL) {
			/* this is  realloc(NULL, n); it's counted as malloc() */

			/* RELAXED should be OK as we don't care about result here */
			__atomic_add_fetch(&ms.ms_allocs, 1, __ATOMIC_RELAXED);
			/* RELAXED should be OK as we don't care about result here */
			__atomic_add_fetch(&ms.ms_total_allocated, sz,
			    __ATOMIC_RELAXED);
			update_alloc(sz);
		} else {
			__atomic_add_fetch(&ms.ms_reallocs, 1, __ATOMIC_RELAXED);
			if (save_mh.mh_size > mh->mh_size) {
				/* memory is shrinking */
				delta = save_mh.mh_size - mh->mh_size;
				update_release(delta);
				__atomic_add_fetch(&ms.ms_total_released, delta,
				    __ATOMIC_RELAXED);
			} else {
				/* memory is growing */
				delta = mh->mh_size - save_mh.mh_size;
				__atomic_add_fetch(&ms.ms_total_allocated, delta,
				    __ATOMIC_RELAXED);
				update_alloc(delta);
			}
		}
	}

	return (rv);
}

static void *
mp_CRYPTO_malloc_trace(unsigned long sz, const char *f, int l)
{
	struct memhdr *mh;
	void *rv;
	mprofile_t *mp = get_mprofile();

	mh = (struct memhdr *) malloc(sz + sizeof (struct memhdr));
	if (mh != NULL) {
		mh->mh_size = sz;
		mh->mh_chk = (uint64_t)mh ^ sz;
		rv = (void *)((char *)mh + sizeof (struct memhdr));
	} else {
		rv = NULL;
	}

	if (mp != NULL)
		mprofile_record_alloc(mp, rv, sz, NULL);

	return (rv);
}

static void
mp_CRYPTO_free_trace(void *b, const char *f, int l)
{
	struct memhdr *mh = NULL;
	mprofile_t *mp = get_mprofile();
	uint64_t chk;

	if (b != NULL) {
		mh = (struct memhdr *)((char *)b - sizeof (struct memhdr));
		chk = (uint64_t)mh ^ mh->mh_size;
		if (chk != mh->mh_chk) {
			fprintf(stderr, "%p memory corruption detected in %s!",
			    b, __func__);
			abort();
		}
	}

	if (mp != NULL)
		mprofile_record_free(mp, b, (b == NULL) ? 0 : mh->mh_size,
		    NULL);
	free(mh);
}

static void *
mp_CRYPTO_realloc_trace(void *b, unsigned long sz, const char *f, int l)
{
	struct memhdr *mh;
	struct memhdr save_mh;
	uint64_t chk;
	mprofile_t *mp = get_mprofile();
	void *rv = NULL;

	if (b != NULL) {
		mh = (struct memhdr *)((char *)b - sizeof (struct memhdr));
		chk = (uint64_t)mh ^ mh->mh_size;
		if (chk != mh->mh_chk) {
			fprintf(stderr, "%p memory corruption detected in %s!",
			    b, __func__);
			abort();
		}
		save_mh = *mh;
	} else {
		mh = NULL;
		save_mh.mh_size = 0;
		save_mh.mh_chk = 0;
	}

	if (sz == 0)
		mprofile_record_free(mp, b, (b == NULL) ? 0 : mh->mh_size, NULL);

	mh = (struct memhdr *)realloc(mh, (sz != 0) ?
	    sz + sizeof (struct memhdr) : 0);
	if (mh == NULL)
		return (NULL);	/* consider recording failure */

	if (sz == 0)
		return (b);

	rv = (void *)((char *)mh + sizeof (struct memhdr));
	if (mp != NULL) {
		mh->mh_size = sz;
		mh->mh_chk = (uint64_t)mh ^ sz;
		if (b == NULL) {
			mprofile_record_alloc(mp, rv, sz, NULL);
		} else {
			mprofile_record_realloc(mp, rv, sz,
			    save_mh.mh_size, b, NULL);
		}
	}

	return (rv);
}

#ifdef _WITH_STACKTRACE

#ifdef USE_LIBUNWIND

#include <libunwind.h>

static void
collect_backtrace(mprofile_stack_t *mps)
{
	unw_cursor_t uw_cursor;
	unw_context_t uw_context;;
	unw_word_t fp;

	unw_getcontext(&uw_context);
	unw_init_local(&uw_cursor, &uw_context);

	do {
		unw_get_reg(&uw_cursor, UNW_REG_IP, &fp);
		mprofile_push_frame(mps, (unsigned long long)fp);
	} while (unw_step(&uw_cursor) > 0);

}
#else	/* !USE_LIBUNWIND */
#include <unwind.h>

static _Unwind_Reason_Code
collect_backtrace(struct _Unwind_Context *uw_context, void *cb_arg)
{
	unsigned long long fp = _Unwind_GetIP(uw_context);
	mprofile_stack_t *mps = (mprofile_stack_t *)cb_arg;

	mprofile_push_frame(mps, fp);

	return (_URC_NO_REASON);
}
#endif	/* USE_LIBUNWIND */

static void *
mp_CRYPTO_malloc_trace_with_stack(unsigned long sz, const char *f, int l)
{
	struct memhdr *mh;
	void *rv;
	mprofile_t *mp = get_mprofile();
	char stack_buf[512];
	mprofile_stack_t *mps = mprofile_init_stack(stack_buf,
	    sizeof (stack_buf));

	mh = (struct memhdr *) malloc(sz + sizeof (struct memhdr));
	if (mh != NULL) {
		mh->mh_size = sz;
		mh->mh_chk = (uint64_t)mh ^ sz;
		rv = (void *)((char *)mh + sizeof (struct memhdr));
	} else {
		rv = NULL;
	}
#ifdef USE_LIBUNWIND
	collect_backtrace(mps);
#else
	_Unwind_Backtrace(collect_backtrace, mps);
#endif
	if (mp != NULL)
		mprofile_record_alloc(mp, rv, sz, mps);

	return (rv);
}

static void
mp_CRYPTO_free_trace_with_stack(void *b, const char *f, int l)
{
	struct memhdr *mh = NULL;
	mprofile_t *mp = get_mprofile();
	uint64_t chk;
	char stack_buf[512];
	mprofile_stack_t *mps = mprofile_init_stack(stack_buf,
	    sizeof (stack_buf));

#ifdef USE_LIBUNWIND
	collect_backtrace(mps);
#else
	_Unwind_Backtrace(collect_backtrace, mps);
#endif

	if (b != NULL) {
		mh = (struct memhdr *)((char *)b - sizeof (struct memhdr));
		chk = (uint64_t)mh ^ mh->mh_size;
		if (chk != mh->mh_chk) {
			fprintf(stderr, "%p memory corruption detected in %s!",
			    b, __func__);
			abort();
		}
	}

	if (mp != NULL)
		mprofile_record_free(mp, b, (b == NULL) ? 0 : mh->mh_size, mps);
	free(mh);
}

static void *
mp_CRYPTO_realloc_trace_with_stack(void *b, unsigned long sz, const char *f,
    int l)
{
	struct memhdr *mh;
	struct memhdr save_mh;
	uint64_t chk;
	mprofile_t *mp = get_mprofile();
	void *rv = NULL;
	char stack_buf[512];
	mprofile_stack_t *mps = mprofile_init_stack(stack_buf,
	    sizeof (stack_buf));;

	if (b != NULL) {
		mh = (struct memhdr *)((char *)b - sizeof (struct memhdr));
		chk = (uint64_t)mh ^ mh->mh_size;
		if (chk != mh->mh_chk) {
			fprintf(stderr, "%p memory corruption detected in %s!",
			    b, __func__);
			abort();
		}
		save_mh = *mh;
	} else {
		mh = NULL;
	}

	if (sz == 0)
		mprofile_record_free(mp, b, (b == NULL) ? 0 : mh->mh_size, mps);

	mh = (struct memhdr *)realloc(mh, (sz != 0) ?
	    sz + sizeof (struct memhdr) : 0);
	if (mh == NULL)
		return (NULL);	/* consider recording failure */

	if (sz == 0)
		return (b);

#ifdef USE_LIBUNWIND
	collect_backtrace(mps);
#else
	_Unwind_Backtrace(collect_backtrace, mps);
#endif
	rv = (void *)((char *)mh + sizeof (struct memhdr));
	if (mp != NULL) {
		mh->mh_size = sz;
		mh->mh_chk = (uint64_t)mh ^ sz;
		if (b == NULL) {
			mprofile_record_alloc(mp, rv, sz, mps);
		} else {
			mprofile_record_realloc(mp, rv, sz,
			    save_mh.mh_size, b, mps);
		}
	}

	return (rv);
}
#endif /* _WITH_STACKTRACE */
