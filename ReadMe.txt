This is a simple memory profiler for OpenSSL. It relies on
CRYPTO_set_mem_functions() to intercept operations on heap
memory.

To build it just type 'make'. Makefile found here
builds libmprofile.so with clang runtime libraries.
Adjust the Makefile to build library with gcc by uncommenting
relevant parts.

By default it is supposed to be preloaded using LD_PRELOAD.
There are two environment variables to control libmprofile.so:
    - MPROFILE_OUTF which specifies path where to store results
    - MPROFILE_MODE which controls level of detail data to collect

To get basic statistics about openssl application one runs
the particular app as follows:
    MPROFILE_OUTF=/tmp/app-stats.json LD_PRELOAD=/path/to/libmprofile.so \
	./particular_openssl_app
The 'particular_openssl_app' must be dynamically linked with OpenSSL's
libcrypto. The command above leaves /tmp/app-stats.json file
which might read as follows:
----8<----
    {
	    "total_allocated_sz" : 267264,
	    "total_released_sz" : 265216,
	    "allocs" : 7,
	    "releases" : 4,
	    "reallocs" : 6,
	    "max" : 262912,
	    "tstart" : {
		    "sec" : 1742555543,
		    "nsec" : 462214094,
	    },
	    "tfinish" : {
		    "sec" : 1742555543,
		    "nsec" : 462513842,
	    }
    }
----8<----
The meaning of fields is self-explanatory. What's worth to note
is that data shows the application leaked some buffers. The
total_allocated_sz does not match total_released_sz. Also
number of alloc operations (allocs) does not match number of
free operations (releases).

Note the library may abort the application when it detects
attempt to free memory using OPENSSL_free() while particular
memory was not allocated by OPENSSL_malloc()/OPENSSL_realloc()
(the memory is unknown to library).

Please see sample-data directory to better understand
different modes discussed here. To generate sample data
just do:
----8<----
cd sample-data
make
----8<----
just make sure you build libmprofile.so first.

MPROFILE_MODE=1
there are 5 profiling modes. The default mode is mode 1 which
collects just basic stats. The files mprofile-*-stats.json
contain the basic stats as shown above.

MPROFILE_MODE=2
Records all calls to OPENSSL_malloc(), OPENSSL_free() and OPENSSL_realloc().
The output can be post-processed to calculate desired stats.
Those samples can be seen in mprofile-*-log.json. One can use
scripts/mprofile.py to analyze the log:
----8<----
./scripts/mprofile.py -m sample-data/mprofile-realloc-log.json 
----8<----
The command above calculates the 'max' value (the maximum memory
used).

MPROFILE_MODE=3
Logs also call stack for every call to OPENSSL_malloc(),
OPENSSL_realloc() and OPENSSL_free(). The sample data
can be seen in sample-data/mprofile-realloc-log-stacks.json file.
To analyze those data just run:
----8<----
./scripts/mprofile.py -o /tmp/mprofile-realloc.html \
    sample-data/mprofile-realloc-log.json 
----8<----
and point your browser to file:///tmp/mprofile-realloc.html
where you will see a plot with allocation curve. Clicking
on the points at the curve you will revel a callstack.

MPROFILE_MODE=4
Connects all recorded operations to chains. So we can trace
the history of particular buffer/address more easily. The
related operations are linked with 'next-id', 'prev-id'
members as seen in sample-data/mprofile-*-log-chain.json files.
This way you can discover which buffers are leaking.

MPROFILE_MODE=5
Full details. This mode creates allocation chains with
callstacks. The sample can be found in
samples/mprofile-*-log-chains-stacks.json. Those data are supposed
to be analyzed by scripts/mprofile.py:
----8<----
./scripts/mprofile.py -o /tmp/mprofile-sha256.html --samples 100 \
    sample-data/mprofile-sha256-log-chains-stacks.json 
----8<----
Not the options '--samples 100' it tells mprofily.py script to construct
the plot only from 100 evenly distributed samples. Trying to use
construct plot from all samples may take your web-browser down.

The size of .json logs varies a lot. It can be dozen of kilobytes
up to 1GB.



