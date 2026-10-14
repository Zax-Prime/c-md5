/**
 * CLI frontend for md5 checksums
 *
 * Author: Zax-Prime
 * License: MIT
 *
 * Attribution:
 * Based on c-md5 originally written by Dave Eddy <ysap@daveeddy.com>.
 */

#include "md5.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <pthread.h>
#define HAVE_PTHREADS 1
#endif

struct file_task {
	const char *path;
	uint8_t digest[16];
	int ret;
};

#ifdef HAVE_PTHREADS
struct pool_state {
	struct file_task *tasks;
	int count;
	int next_idx;
	pthread_mutex_t lock;
};

static void *worker_func(void *arg) {
	struct pool_state *pool = (struct pool_state *)arg;

	while (true) {
		int idx = -1;
		pthread_mutex_lock(&pool->lock);
		if (pool->next_idx < pool->count)
			idx = pool->next_idx++;
		pthread_mutex_unlock(&pool->lock);

		if (idx == -1)
			break;

		pool->tasks[idx].ret = md5_file(pool->tasks[idx].path,
		    pool->tasks[idx].digest);
	}
	return NULL;
}
#endif

int main(int argc, char **argv) {
	// read from stdin if no arguments or single "-"
	if (argc <= 1 || (argc == 2 && strcmp(argv[1], "-") == 0)) {
		uint8_t digest[16];
		if (md5_fd(0, digest) != 0)
			return 1;
		char hex[33];
		md5_to_hex(digest, hex);
		puts(hex);
		return 0;
	}

	// single file argument: print hash directly
	if (argc == 2) {
		uint8_t digest[16];
		if (md5_file(argv[1], digest) != 0)
			return 1;
		char hex[33];
		md5_to_hex(digest, hex);
		puts(hex);
		return 0;
	}

	// multiple files
	int count = argc - 1;
	struct file_task *tasks = calloc((size_t)count, sizeof (*tasks));
	if (!tasks) {
		perror("calloc");
		return 1;
	}

	for (int i = 0; i < count; i++)
		tasks[i].path = argv[i + 1];

#ifdef HAVE_PTHREADS
	long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	if (nprocs < 1)
		nprocs = 1;
	if (nprocs > count)
		nprocs = count;

	struct pool_state pool = {
		.tasks = tasks,
		.count = count,
		.next_idx = 0,
		.lock = PTHREAD_MUTEX_INITIALIZER,
	};

	pthread_t *threads = calloc((size_t)nprocs, sizeof (*threads));
	if (threads) {
		for (long i = 0; i < nprocs; i++)
			pthread_create(&threads[i], NULL, worker_func, &pool);
		for (long i = 0; i < nprocs; i++)
			pthread_join(threads[i], NULL);
		free(threads);
	} else {
		for (int i = 0; i < count; i++)
			tasks[i].ret = md5_file(tasks[i].path, tasks[i].digest);
	}
#else
	for (int i = 0; i < count; i++)
		tasks[i].ret = md5_file(tasks[i].path, tasks[i].digest);
#endif

	int exit_code = 0;
	for (int i = 0; i < count; i++) {
		if (tasks[i].ret != 0) {
			exit_code = 1;
			continue;
		}
		char hex[33];
		md5_to_hex(tasks[i].digest, hex);
		printf("%s  %s\n", hex, tasks[i].path);
	}

	free(tasks);
	return exit_code;
}
