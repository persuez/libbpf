#include <linux/ptrace.h>

#include "libbpf_kernel.h"

struct bpf_map_def SEC("maps") programs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = 4,
	.value_size = 4,
	.max_entries = 1024,
};

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_kpobe_program(struct pt_regs *ctx)
{
	int key = 1;

	/* dispatch into next BPF program */
	bpf_tail_call(ctx, &programs, key);

	/* fall through when the program descriptor is not in the map */
	char fmt[] = "missing program in prog_array map\n";
	bpf_trace_printk(fmt, sizeof(fmt));
	return 0;
}

char _license[] SEC("license") = "GPL";
