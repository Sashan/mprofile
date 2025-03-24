#ifndef	_KELF_H_
#define	_KELF_H_

struct syms;

struct syms* kelf_open(const char *, struct syms *, unsigned long);
void kelf_close(struct syms *);
int kelf_snprintsym(struct syms *, char *, size_t, unsigned long,
    unsigned long);

#endif
