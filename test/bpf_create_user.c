#include <stdio.h>
#include <linux/bpf.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "libbpf.h"

int main()
{
	int key, value, result, fd;

	key = 1, value = 1234;

	fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(int), sizeof(int), 100, BPF_F_NO_PREALLOC);
	if (fd < 0) {
		perror("bpf_create_map fail");
		exit(1);
	}
	result = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
	if (result == 0) {
		printf("Map updated with new element\n");
	}
	else {
		printf("Failed to update map with new value: %d (%s)\n",
				result, strerror(errno));
	}

	return 0;
}
