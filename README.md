md5 Implemented in C
====================

Fast, portable C implementation of the MD5 checksum algorithm.

Build
-----

```sh
make
```

Or manually:

```sh
clang -O3 md5.c main.c -pthread -o md5
```

Usage
-----

Single file or standard input:

```sh
./md5 file.txt
./md5 < file.bin
echo -n 'hello' | ./md5
```

Multiple files (processed in parallel across available CPU cores):

```sh
./md5 file1.bin file2.bin file3.bin
```

Testing
-------

Run the test suite including edge case boundary checks:

```sh
make test
```

Library Usage
-------------

Include `md5.h` in your project:

```c
#include "md5.h"

// Stream API
struct md5_ctx ctx;
md5_init(&ctx);
md5_update(&ctx, buffer, len);
uint8_t digest[16];
md5_final(&ctx, digest);

char hex[33];
md5_to_hex(digest, hex);

// Or hash a file directly
md5_file("path/to/file", digest);
```

Authors & Attribution
---------------------

Maintained and optimized by Zax-Prime.

This project is a fork of [bahamas10/c-md5](https://github.com/bahamas10/c-md5),
originally written by Dave Eddy.

License
-------

MIT License
