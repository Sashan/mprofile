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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "utils/tree.h"
#include "mprofile.h"

#define	MPS_STACK_DEPTH		64

#define	MPS_FLAG_MANAGED	1

struct mprofile_stack {
	size_t				 mps_stack_limit;
	unsigned int			 mps_id;
	unsigned int			 mps_stack_depth;
	unsigned int			 mps_flags;
	unsigned int			 mps_count;
	pthread_t			 mps_thread;
	RB_ENTRY(mprofile_stack)	 mps_rbe;
	RB_ENTRY(mprofile_stack)	 mps_id_rbe;
	unsigned long long		*mps_stack;
};

struct mprofile_stack_set {
	unsigned int	 			stset_id;
	RB_HEAD(mp_stack_set, mprofile_stack)	stset_rbh;
	RB_HEAD(mp_stack_id, mprofile_stack)	stset_id_rbh;
};

static int stack_compare(mprofile_stack_t *, mprofile_stack_t *);
static int stack_id_compare(mprofile_stack_t *, mprofile_stack_t *);

RB_GENERATE_STATIC(mp_stack_set, mprofile_stack, mps_rbe, stack_compare);
RB_GENERATE_STATIC(mp_stack_id, mprofile_stack, mps_id_rbe, stack_id_compare);

static int
stack_compare(mprofile_stack_t *a_mps, mprofile_stack_t *b_mps)
{
	int	i = 0;

	if (a_mps->mps_stack_depth < b_mps->mps_stack_depth)
		return (-1);
	else if (a_mps->mps_stack_depth > b_mps->mps_stack_depth)
		return (1);
	else while ((a_mps->mps_stack[i] == b_mps->mps_stack[i]) &&
	    (i < b_mps->mps_stack_depth))
		i++;

	if (i == b_mps->mps_stack_depth)
		i--;

	if (a_mps->mps_stack[i] < b_mps->mps_stack[i])
		return (-1);
	else if (a_mps->mps_stack[i] > b_mps->mps_stack[i])
		return (1);

	return (0);
}

static int
stack_id_compare(mprofile_stack_t *a_mps, mprofile_stack_t *b_mps)
{
	if (a_mps->mps_id < b_mps->mps_id)
		return (-1);
	else if (a_mps->mps_id > b_mps->mps_id)
		return (1);
	else
		return (0);
}

mprofile_stack_t *
mprofile_init_stack(char *buf, size_t buf_sz)
{
	mprofile_stack_t *mps;
	unsigned char *stack_start;
	size_t		  stack_sz;

	if (buf == NULL) {
		stack_sz =
		    sizeof (mprofile_stack_t) +
		    sizeof (unsigned long long) * MPS_STACK_DEPTH;
		mps = (mprofile_stack_t *) malloc(stack_sz);
		if (mps == NULL)
			return (NULL);
		stack_start = (unsigned char *)mps;
		mps += sizeof (mprofile_stack_t);
		mps->mps_stack = (unsigned long long *)stack_start;
		mps->mps_flags = MPS_FLAG_MANAGED;
		mps->mps_stack_depth = 0;
		mps->mps_stack_limit = MPS_STACK_DEPTH;
		mps->mps_thread = pthread_self();
		mps->mps_count = 0;
		memset(mps->mps_stack, 0,
		    sizeof (unsigned long long) * MPS_STACK_DEPTH);
	} else {
		if (buf_sz <
		    (sizeof (mprofile_stack_t) + (sizeof (unsigned long long))))
			return NULL;
		memset(buf, 0, buf_sz);
		mps = (mprofile_stack_t *)buf;
		stack_start = (unsigned char *)buf;
		stack_start += sizeof (mprofile_stack_t);
		mps->mps_stack = (unsigned long long *)stack_start;
		stack_sz = buf_sz - sizeof (mprofile_stack_t);
		mps->mps_stack_limit = stack_sz / sizeof (unsigned long long);
		mps->mps_stack_depth = 0;
		memset(mps->mps_stack, 0, stack_sz);
	}

	return (mps);
}

mprofile_stack_t *
mprofile_copy_stack(mprofile_stack_t *mps)
{
	mprofile_stack_t *new_mps;
	unsigned char *stack_start;
	unsigned int i;

	new_mps = (mprofile_stack_t *) malloc(
		sizeof (mprofile_stack_t) +
		(sizeof (unsigned long long) * (mps->mps_stack_depth + 1)));
	if (new_mps == NULL)
		return (NULL);

	stack_start = (unsigned char *)new_mps;
	stack_start += sizeof (mprofile_stack_t);
	new_mps->mps_stack = (unsigned long long *)stack_start;

	for (i = 0; i < mps->mps_stack_depth; i++)
		new_mps->mps_stack[i] = mps->mps_stack[i];

	new_mps->mps_stack_depth = mps->mps_stack_depth;
	/* using stack_depth here freezes the stack */
	new_mps->mps_stack_limit = mps->mps_stack_depth;
	new_mps->mps_flags = MPS_FLAG_MANAGED;
	if (mps->mps_flags == MPS_FLAG_MANAGED) {
		new_mps->mps_count = mps->mps_count;
		new_mps->mps_thread = mps->mps_thread;
	} else {
		new_mps->mps_count = 1;
		new_mps->mps_thread = 0; /* get thread id */
	}

	return (new_mps);
}

mprofile_stack_t *
mprofile_add_stack(mprofile_stset_t *stset, mprofile_stack_t *new_mps)
{
	mprofile_stack_t	*mps;

	if (stset == NULL)
		return (NULL);

	mps = RB_FIND(mp_stack_set, &stset->stset_rbh, new_mps);
	if (mps != NULL) {
		mps->mps_count++;
	} else {
		mps = mprofile_copy_stack(new_mps);
		if (mps == NULL)
			return (NULL);
		mps->mps_id = stset->stset_id++;
		RB_INSERT(mp_stack_set, &stset->stset_rbh, mps);
		RB_INSERT(mp_stack_id, &stset->stset_id_rbh, mps);
	}

	return (mps);
}

void
mprofile_destroy_stack(mprofile_stack_t *mps)
{
	assert(mps->mps_flags == MPS_FLAG_MANAGED);

	free(mps);
}

void
mprofile_push_frame(mprofile_stack_t *mps, unsigned long long frame)
{
	if (mps == NULL)
		return;

	if (mps->mps_stack_depth < mps->mps_stack_limit) {
		mps->mps_stack[mps->mps_stack_depth] = frame;
		mps->mps_stack_depth++;
	}
}

mprofile_stset_t *
mprofile_create_stset(void)
{
	mprofile_stset_t *stset;

	stset = (mprofile_stset_t *) malloc(sizeof (mprofile_stset_t));
	if (stset != NULL) {
		RB_INIT(&stset->stset_rbh);
		RB_INIT(&stset->stset_id_rbh);
		stset->stset_id = 1;
	}

	return (stset);
}

void
mprofile_destroy_stset(mprofile_stset_t *stset)
{
	struct mprofile_stack *mps, *walk;

	if (stset == NULL)
		return;

	RB_FOREACH_SAFE(mps, mp_stack_set, &stset->stset_rbh, walk) {
		RB_REMOVE(mp_stack_set, &stset->stset_rbh, mps);
		RB_REMOVE(mp_stack_id, &stset->stset_id_rbh, mps);
		mprofile_destroy_stack(mps);
	}

	free(stset);
}

mprofile_stack_t *
mprofile_get_next_stack(mprofile_stset_t *stset, mprofile_stack_t *mps)
{
	if (stset == NULL)
		return (NULL);

	if (mps == NULL)
		return (RB_MIN(mp_stack_set, &stset->stset_rbh));

	return (RB_NEXT(mp_stack_set, &stset->stset_rbh, mps));
}

void
mprofile_walk_stack(mprofile_stack_t *mps,
    void(*walk_f)(unsigned long long, void *), void *walk_arg)
{
	unsigned int i;

	for (i = 0; i < mps->mps_stack_depth; i++)
		walk_f(mps->mps_stack[i], walk_arg);
}

unsigned int
mprofile_get_stack_id(mprofile_stack_t *mps)
{
	if (mps == NULL)
		return (0);

	return (mps->mps_id);
}

unsigned int
mprofile_get_stack_count(mprofile_stack_t *mps)
{
	if (mps == NULL)
		return (0);

	return (mps->mps_count);
}

unsigned long long
mprofile_get_thread_id(mprofile_stack_t *mps)
{
	if (mps == NULL)
		return (0);

	return ((unsigned long long)mps->mps_thread);
}

mprofile_stack_t *
mprofile_merge_stack(mprofile_stset_t *dst_stset, mprofile_stset_t *src_stset,
    unsigned int stack_id)
{
	mprofile_stack_t	*old_mps, *new_mps;
	mprofile_stack_t	 key = { 0 };

	key.mps_id = stack_id;
	old_mps = RB_FIND(mp_stack_id, &src_stset->stset_id_rbh, &key);
	assert(old_mps != NULL);

	/*
	 *  if there is single instance just try to move it.
	 */
	if (old_mps->mps_count == 1) {
		RB_REMOVE(mp_stack_set, &src_stset->stset_rbh, old_mps);
		RB_REMOVE(mp_stack_id, &src_stset->stset_id_rbh, old_mps);
		new_mps = RB_INSERT(mp_stack_set, &dst_stset->stset_rbh,
		    old_mps);
		if (new_mps == NULL) {
			mprofile_stack_t *chk_mps_id;
			chk_mps_id = RB_INSERT(mp_stack_id,
			    &dst_stset->stset_id_rbh, old_mps);
			if (chk_mps_id != NULL) {
				/*
				 * need to generate new stack set id
				 * and insert it.
				 */
				old_mps->mps_id = dst_stset->stset_id++;
				chk_mps_id = RB_INSERT(mp_stack_id,
				    &dst_stset->stset_id_rbh, old_mps);
				assert(chk_mps_id == NULL);
			}
			/*
			 * when moving then we must get new stack id,
			 * which is unique for destination set.
			 */
			new_mps = old_mps;
		} else {
			/* same stack exists in dst_stset, then just free it */
			free(old_mps);
			new_mps->mps_count++;
		}
	} else {
		/* check if the same stack exists in destination */
		new_mps = RB_FIND(mp_stack_set, &dst_stset->stset_rbh,
		    old_mps);
		if (new_mps == NULL) {
			/*
			 * we must insert copy to destination, because
			 * mps_count > 1
			 */
			new_mps = mprofile_add_stack(dst_stset, old_mps);
			if (new_mps == NULL) {
				perror("No memory");
				abort();
			}
		} else {
			new_mps->mps_count++;
		}
		old_mps->mps_count--;
	}

	return (new_mps);
}
