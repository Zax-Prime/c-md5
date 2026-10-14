md5 Implemented in C
====================

C implementation of the md5 checksum algorithm

Usage
----

```
clang md5.c -o md5
./md5 file.txt
./md5 < file.bin
echo 'hello' | ./md5
DEBUG=1 ./md5 file.txt
```

Attribution
-----------

This project is a fork of [bahamas10/c-md5](https://github.com/bahamas10/c-md5),
originally written by Dave Eddy.

License
-------

MIT License
