#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

static void
do_sha256(void)
{
	unsigned char	 md_value[EVP_MAX_MD_SIZE];
	EVP_MD		*md_sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
	EVP_MD_CTX	*md_ctx = EVP_MD_CTX_new();
	unsigned int	 md_len;

	if (md_ctx == NULL || md_sha256 == NULL)
		goto done;

	memset(md_value, 0, sizeof (md_value));
	EVP_DigestInit_ex2(md_ctx, md_sha256, NULL);
	EVP_DigestUpdate(md_ctx, "Part 1",sizeof ("Part 1") - 1);
	EVP_DigestUpdate(md_ctx, "Part 2",sizeof ("Part 2") - 1);
	EVP_DigestFinal_ex(md_ctx, md_value, &md_len);
done:
	EVP_MD_CTX_free(md_ctx);
	EVP_MD_free(md_sha256);
}

int
main(int argc, const char *argv[])
{
	do_sha256();

        return (0);
}
