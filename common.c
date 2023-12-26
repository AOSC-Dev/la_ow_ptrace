#include <asm-generic/unistd.h>

#undef __SYSCALL
#define __SYSCALL(nr, func) [nr] = #func,

// add newfstat/newfstatat to table
#define __ARCH_WANT_NEW_STAT
#define __ARCH_WANT_SYS_CLONE3
#define __ARCH_WANT_SET_GET_RLIMIT
const char *syscall_name_table[__NR_syscalls] = {
#include <asm-generic/unistd.h>
};
#undef __ARCH_WANT_NEW_STAT
#undef __ARCH_WANT_SYS_CLONE3
#undef __ARCH_WANT_SET_GET_RLIMIT