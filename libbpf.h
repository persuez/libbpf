#ifndef RAW_INSN_H
#define RAW_INSN_H

#include <linux/bpf.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <linux/perf_event.h>

#include "libbpf_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BPF_CALL_FUNC(FUNC) \
	((struct bpf_insn) {                                    \
		.code = BPF_JMP | BPF_CALL | BPF_K,				\
		.dst_reg = 0,	\
		.src_reg = 0,	\
		.off = 0, \
		.imm = FUNC })

#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_ENDIAN(TYPE, DST, LEN)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_END | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = LEN })

#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0,					\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })

#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

#define BPF_MOV64_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_LD_IND(SIZE, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND,	\
		.dst_reg = 0,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

#define BPF_STX_XADD(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_XADD,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

#define BPF_EMIT_CALL(FUNC)					\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((FUNC) - BPF_FUNC_unspec) })

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })

#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

struct bpf_create_map_attr {
        const char *name;
        enum bpf_map_type map_type;
        __u32 map_flags;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
        __u32 numa_node;
        __u32 btf_fd;
        __u32 btf_key_type_id;
        __u32 btf_value_type_id;
        __u32 map_ifindex;
        __u32 inner_map_fd;
};

struct bpf_load_program_attr {
	enum bpf_prog_type prog_type;
	enum bpf_attach_type expected_attach_type;
	const char *name;
	const struct bpf_insn *insns;
	size_t insns_cnt;
	const char *license;
	__u32 kern_version;
	__u32 prog_ifindex;
	__u32 prog_btf_fd;
	__u32 func_info_rec_size;
	const void *func_info;
	__u32 func_info_cnt;
	__u32 line_info_rec_size;
	const void *line_info;
	__u32 line_info_cnt;
	__u32 log_level;
	__u32 prog_flags;
};

static uint64_t ptr_to_u64(const void *ptr)
{
	return (uint64_t)(unsigned long)ptr;
}

#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# else
#  warning __NR_bpf not defined.
# endif
#endif

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
#ifdef __NR_bpf
	return syscall(__NR_bpf, cmd, attr, size);
#else
	errno = ENOSYS;
	return -2;
#endif
}

static inline int sys_bpf_prog_load(union bpf_attr *attr, unsigned int size)
{
	int fd;

	do {
		fd = sys_bpf(BPF_PROG_LOAD, attr, size);
	} while (fd < 0 && errno == EAGAIN);

	return fd;
}

static inline int
sys_perf_event_open(struct perf_event_attr *attr,
		      pid_t pid, int cpu, int group_fd,
		      unsigned long flags)
{
	int fd;

	fd = syscall(__NR_perf_event_open, attr, pid, cpu,
		     group_fd, flags);

	return fd;
}

#define MAX_MAPS 32
#define MAX_PROGS 32

struct bpf_load_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int numa_node;
};

struct bpf_map_data {
	int fd;
	char *name;
	size_t elf_offset;
	struct bpf_load_map_def def;
};

typedef void (*fixup_map_cb)(struct bpf_map_data *map, int idx);

extern int prog_fd[MAX_PROGS];
extern int event_fd[MAX_PROGS];
extern char bpf_log_buf[BPF_LOG_BUF_SIZE];
extern int prog_cnt;

/* There is a one-to-one mapping between map_fd[] and map_data[].
 * The map_data[] just contains more rich info on the given map.
 */
extern int map_fd[MAX_MAPS];
extern struct bpf_map_data map_data[MAX_MAPS];
extern int map_data_count;
extern struct bpf_map_data map_data[MAX_MAPS];

extern int load_bpf_file(char *path);

extern int bpf_create_map(enum bpf_map_type map_type, int key_size,
		int value_size, int max_entries, __u32 map_flags);
extern int bpf_map_update_elem(int fd, const void *key, const void *value,
			__u64 flags);
extern int bpf_map_lookup_elem(int fd, const void *key, void *value);
extern int bpf_map_delete_elem(int fd, const void *key);
extern int bpf_map_get_next_key(int fd, const void *key, void *next_key);
extern int bpf_map_lookup_and_delete_elem(int fd, const void *key, void *value);
/*
extern int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns,
                  size_t num_insns, const char *license, char *log,
                  size_t size_log);
*/
extern int bpf_load_program(enum bpf_prog_type type, const struct bpf_insn *insns,
		     size_t insns_cnt, const char *license,
		     __u32 kern_version, char *log_buf,
		     size_t log_buf_sz);
extern void read_trace_pipe(void);
extern int bpf_obj_pin(int fd, const char *pathname);
extern int bpf_obj_get(const char *pathname);
#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* RAW_INSN_H */
