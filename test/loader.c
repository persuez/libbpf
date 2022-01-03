#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <string.h>
#include <errno.h>

#include "libbpf.h"

int main()
{
	int key = 1, prog_fd, err;
	struct bpf_insn prog[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0), // assign r0 = 0
		BPF_EXIT_INSN(), // return r0
	};
	char buf[128];

	if (load_bpf_file("tail_call.o") != 0) {
		printf("The kernel didn't load the BPF program\n");
		exit(2);
	}
	prog_fd = bpf_load_program(BPF_PROG_TYPE_TRACEPOINT, prog, sizeof(prog)/sizeof(prog[0]), "GPL", 0, buf, 128);
	if (prog_fd < 0) {
		perror("bpf_prog_load fail");
		exit(1);
	}
	printf("map_data[0].fd is %d, prog_fd is %d\n", map_data[0].fd, prog_fd);
	err = bpf_map_update_elem(map_data[0].fd, &key, &prog_fd, BPF_ANY);
	if (err < 0) {
		perror("bpf_map_update_elem fail");
		exit(3);
	}

	read_trace_pipe();

	exit(0);
}
