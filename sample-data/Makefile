CPPFLAGS+=-I$(OPENSSL_HEADERS)
CPPFLAGS+=-g
CPPFLAGS+=-O0
## adjust when libcrypto is not in default library path
#LDFLAGS=-L$(OPENSSL_LIB_PATH)

all:	mprofile-sha256-stats.json \
	mprofile-sha256-log.json \
	mprofile-sha256-log-stacks.json \
	mprofile-sha256-log-chains.json \
	mprofile-sha256-log-chains-stacks.json \
	mprofile-realloc-stats.json \
	mprofile-realloc-log.json \
	mprofile-realloc-log-stacks.json \
	mprofile-realloc-log-chains.json \
	mprofile-realloc-log-stacks.json \
	mprofile-realloc-log-chains-stacks.json

mprofile-sha256-stats.json: sha256
	LD_PRELOAD=../libmprofile.so MPROFILE_OUTF=./mprofile-sha256-stats.json \
	    MPROFILE_MODE=1 ./sha256

mprofile-sha256-log.json: sha256
	LD_PRELOAD=../libmprofile.so MPROFILE_OUTF=./mprofile-sha256-log.json \
	    MPROFILE_MODE=2 ./sha256

mprofile-sha256-log-stacks.json: sha256
	LD_PRELOAD=../libmprofile.so \
	    MPROFILE_OUTF=./mprofile-sha256-log-stacks.json \
	    MPROFILE_MODE=3 ./sha256

mprofile-sha256-log-chains.json: sha256
	LD_PRELOAD=../libmprofile.so \
	    MPROFILE_OUTF=./mprofile-sha256-log-chains.json \
	    MPROFILE_MODE=4 ./sha256

mprofile-sha256-log-chains-stacks.json: sha256
	LD_PRELOAD=../libmprofile.so \
	    MPROFILE_OUTF=./mprofile-sha256-log-chains-stacks.json \
	    MPROFILE_MODE=5 ./sha256

mprofile-realloc-stats.json: realloc
	LD_PRELOAD=../libmprofile.so \
	    MPROFILE_OUTF=./mprofile-realloc-stats.json \
	    MPROFILE_MODE=1 ./realloc

mprofile-realloc-log.json: realloc
	LD_PRELOAD=../libmprofile.so MPROFILE_OUTF=./mprofile-realloc-log.json \
	    MPROFILE_MODE=2 ./realloc

mprofile-realloc-log-stacks.json: realloc
	LD_PRELOAD=../libmprofile.so \
	    MPROFILE_OUTF=./mprofile-realloc-log-stacks.json \
	    MPROFILE_MODE=3 ./realloc

mprofile-realloc-log-chains.json: realloc
	LD_PRELOAD=../libmprofile.so \
	    MPROFILE_OUTF=./mprofile-realloc-log-chains.json \
	    MPROFILE_MODE=4 ./realloc

mprofile-realloc-log-chains-stacks.json: realloc
	LD_PRELOAD=../libmprofile.so \
	    MPROFILE_OUTF=./mprofile-realloc-log-chains-stacks.json \
	    MPROFILE_MODE=5 ./realloc

sha256: sha256.c
	$(CC) $(CPPFLAGS)  -o sha256 sha256.c $(LDFLAGS) -lcrypto

realloc: realloc.c
	$(CC) $(CPPFLAGS)  -o realloc realloc.c $(LDFLAGS) -lcrypto

clean:
	rm -f sha256 realloc *.json
