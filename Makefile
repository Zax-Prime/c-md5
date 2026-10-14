CC = clang
CFLAGS ?= -O3 -Wall -Wextra
LDFLAGS ?= -pthread

all: md5

md5: md5.c main.c md5.h
	$(CC) $(CFLAGS) md5.c main.c $(LDFLAGS) -o md5

test: md5 test-edge-cases
	./test-md5
	./test-edge-cases

test-edge-cases: test-edge-cases.c md5.c md5.h
	$(CC) $(CFLAGS) md5.c test-edge-cases.c $(LDFLAGS) -o test-edge-cases

clean:
	rm -f md5 test-edge-cases

.PHONY: all test clean
