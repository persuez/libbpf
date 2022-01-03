#ifndef __LIBBPF_LIBBPF_INTERNAL_H
#define __LIBBPF_LIBBPF_INTERNAL_H

#ifndef min
# define min(x, y) ((x) < (y) ? (x) : (y))
#endif

/* Recommend log buffer size */
#define BPF_LOG_BUF_SIZE (UINT32_MAX >> 8) /* verifier maximum in kernels <= 5.1 */

#endif
