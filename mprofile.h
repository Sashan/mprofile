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
#ifndef _MPROFILE_H_
#define	_MPROFILE_H_
#include <stdio.h>

typedef struct mprofile_stack mprofile_stack_t;
typedef struct mprofile_stack_set mprofile_stset_t;
typedef struct mprofile mprofile_t;

#ifdef _WITH_STACKTRACE
mprofile_stset_t *mprofile_create_stset();
void mprofile_destroy_stset(mprofile_stset_t *);
mprofile_stack_t * mprofile_add_stack(mprofile_stset_t *, mprofile_stack_t *);
mprofile_stack_t *mprofile_get_next_stack(mprofile_stset_t *,
    mprofile_stack_t *);
mprofile_stack_t *mprofile_init_stack(char *, size_t);
mprofile_stack_t *mprofile_copy_stack(mprofile_stack_t *);
void mprofile_walk_stack(mprofile_stack_t *,
    void(*)(unsigned long long, void *), void *);
void mprofile_destroy_stack(mprofile_stack_t *);
void mprofile_push_frame(mprofile_stack_t *, unsigned long long);
unsigned int mprofile_get_stack_count(mprofile_stack_t *);
unsigned int mprofile_get_stack_id(mprofile_stack_t *);
unsigned long long mprofile_get_thread_id(mprofile_stack_t *);
mprofile_stack_t *mprofile_merge_stack(mprofile_stset_t *, mprofile_stset_t *,
    unsigned int);
#endif

void mprofile_record_alloc(mprofile_t *, void *, size_t, mprofile_stack_t *);
void mprofile_record_free(mprofile_t *,void *, size_t, mprofile_stack_t *);
void mprofile_record_realloc(mprofile_t *, void *, size_t, size_t, void *,
    mprofile_stack_t *);

mprofile_t *mprofile_create(void);
void mprofile_destroy(mprofile_t *);
void mprofile_add(mprofile_t *);
void mprofile_save(FILE*, int);
void mprofile_init(void);
void mprofile_done(void);
const char *mprofile_get_annotation(void);
#endif
