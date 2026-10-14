md5 Implemented in C
====================

C implementation of the md5 checksum algorithm

Usage
----

```
clang -O2 md5.c -o md5
./md5 file.txt
./md5 < file.bin
echo 'hello' | ./md5
DEBUG=1 ./md5 file.txt
```

Build with `-O2` or `-O3`, without it the hash runs about 4x slower. The code
is plain C and doesn't need `-march=native` to be fast.

Attribution
-----------

This project is a fork of [bahamas10/c-md5](https://github.com/bahamas10/c-md5),
originally written by Dave Eddy.

License
-------

MIT License
