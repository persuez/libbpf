#include <asm/types.h>
#include <linux/ptrace.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/version.h>

#include "libbpf_kernel.h"

typedef int32_t s32;
typedef int64_t s64;
typedef uint32_t u32;
typedef uint64_t u64;

struct bpf_map_def SEC("maps") counters = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = 64,
};
struct bpf_map_def SEC("maps") values = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(u64),
	.max_entries = 64,
};
struct bpf_map_def SEC("maps") values2 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct bpf_perf_event_value),
	.max_entries = 64,
};

SEC("kprobe/htab_map_get_next_key")
int bpf_prog1(struct pt_regs *ctx)
{
	u32 key = bpf_get_smp_processor_id();
	u64 count, *val;
	s64 error;

	count = bpf_perf_event_read(&counters, key);
	error = (s64)count;
	if (error <= -2 && error >= -22)
		return 0;

	bpf_printk("read key1 %d", key);
	val = bpf_map_lookup_elem(&values, &key);
	if (val)
		*val = count;
	else
		bpf_map_update_elem(&values, &key, &count, BPF_NOEXIST);

	return 0;
}

SEC("kprobe/htab_map_lookup_elem")
int bpf_prog2(struct pt_regs *ctx)
{
	u32 key = bpf_get_smp_processor_id();
	struct bpf_perf_event_value *val, buf;
	int error;

	error = bpf_perf_event_read_value(&counters, key, &buf, sizeof(buf));
	if (error) {
		bpf_printk("read value fail");
		return 0;
	}

	val = bpf_map_lookup_elem(&values2, &key);
	bpf_printk("read key %d", key);
	if (val)
		*val = buf;
	else
		bpf_map_update_elem(&values2, &key, &buf, BPF_NOEXIST);

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
