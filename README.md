# libbpf
for Book LinuxObservabilitywithBPF

# enviroment
```sh
$ cat /etc/issue
Ubuntu 20.04.2 LTS \n \l
$ uname -r
5.11.0-41-generic
$ clang -v
clang version 10.0.0-4ubuntu1 
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/3.4.6
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/9
Found candidate GCC installation: /usr/lib/gcc/x86_64-linux-gnu/3.4.6
Found candidate GCC installation: /usr/lib/gcc/x86_64-linux-gnu/9
Selected GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/9
Candidate multilib: .;@m64
Candidate multilib: 32;@m32
Candidate multilib: x32;@mx32
Selected multilib: .;@m64
```
# how to compile
```sh
$ clang libbpf.c -shared -fPIC -o libbpf.so
$ sudo cp libbpf.so /lib/x86_64-linux-gnu/
```

# examples
Examples in libbpf/test.
## user-space
Just `#include "libbpf.h"` is ok.Like `bpf_create_user.c`
```c
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
```
A very simple example. How to compile it? just:
```sh
$ clang bpf_create_user.c -L.. -lbpf -lelf -I..
```

## kernel-space
Just `#include "libbpf_kernel.h"` is ok.
Like `tail_call.c`.
```c
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
```
Compile it:
```sh
clang -O2 -target bpf -c tail_call.c -o tail_call.o -I..
```
