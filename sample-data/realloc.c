#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>


static void *allocate_by_realloc = NULL;
static void *allocate_by_malloc = NULL;
static void *free_by_realloc = NULL;
static void *mem_leak = NULL;


int
main(int argc, const char *argv[])
{
	void *tmp;

	allocate_by_malloc = CRYPTO_malloc(256, __FILE__, __LINE__);
	allocate_by_realloc = CRYPTO_realloc(allocate_by_realloc, 256,
	    __FILE__, __LINE__);
	free_by_realloc = CRYPTO_malloc(512, __FILE__, __LINE__);

	/* change sizes by realloc */
	tmp = CRYPTO_realloc(allocate_by_realloc, 256 * 1024,
	    __FILE__, __LINE__);
	if (tmp != NULL)
		allocate_by_realloc = tmp;

	tmp  = CRYPTO_realloc(allocate_by_malloc, 128,
	    __FILE__, __LINE__);
	if (tmp != NULL)
		allocate_by_malloc = tmp;

	/* shrink memory so we get chain of 4 operations */
	tmp = CRYPTO_realloc(allocate_by_realloc, 4096, __FILE__, __LINE__);
	if (tmp != NULL)
		allocate_by_realloc = tmp;
	
	mem_leak = CRYPTO_malloc(1024, __FILE__, __LINE__);

	CRYPTO_free(allocate_by_realloc, __FILE__, __LINE__);
	free_by_realloc = CRYPTO_realloc(free_by_realloc, 0,
	    __FILE__, __LINE__);
	CRYPTO_free(allocate_by_malloc, __FILE__, __LINE__);

	allocate_by_malloc = CRYPTO_malloc(256, __FILE__, __LINE__);
	CRYPTO_free(allocate_by_malloc, __FILE__, __LINE__);

	/* leak */
	allocate_by_malloc = CRYPTO_malloc(1024, __FILE__, __LINE__);
	tmp = CRYPTO_realloc(allocate_by_malloc, 512, __FILE__, __LINE__);

	/* another leak */
	mem_leak = CRYPTO_realloc(NULL, 2048, __FILE__, __LINE__);
	mem_leak = CRYPTO_realloc(mem_leak, 1024, __FILE__, __LINE__);
	mem_leak = CRYPTO_realloc(mem_leak, 512, __FILE__, __LINE__);

        return (0);
}
