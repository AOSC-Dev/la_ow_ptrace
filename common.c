#include <asm-generic/unistd.h>

#define SYSCALL(name) [__NR_##name] = #name

const char *syscall_name_table[__NR_syscalls] = {SYSCALL(brk),
                                                 SYSCALL(close),
                                                 SYSCALL(execve),
                                                 SYSCALL(mmap),
                                                 SYSCALL(mprotect),
                                                 SYSCALL(openat),
                                                 SYSCALL(faccessat),
                                                 SYSCALL(read),
                                                 SYSCALL(munmap),
                                                 SYSCALL(set_tid_address),
                                                 SYSCALL(set_robust_list),
                                                 SYSCALL(ioctl),
                                                 SYSCALL(getrandom),
                                                 SYSCALL(clone),
                                                 SYSCALL(prctl),
                                                 SYSCALL(wait4),
                                                 SYSCALL(lseek),
                                                 SYSCALL(getdents64),
                                                 SYSCALL(getuid),
                                                 SYSCALL(getgid),
                                                 SYSCALL(geteuid),
                                                 SYSCALL(getegid),
                                                 SYSCALL(dup3),
                                                 SYSCALL(getpid),
                                                 SYSCALL(getppid),
                                                 SYSCALL(getpgid),
                                                 SYSCALL(setpgid),
                                                 SYSCALL(setgid),
                                                 SYSCALL(setuid),
                                                 SYSCALL(uname),
                                                 SYSCALL(rt_sigprocmask),
                                                 SYSCALL(rt_sigaction),
                                                 SYSCALL(rt_sigpending),
                                                 SYSCALL(rt_sigtimedwait),
                                                 SYSCALL(rt_sigsuspend),
                                                 SYSCALL(fcntl),
                                                 SYSCALL(dup),
                                                 SYSCALL(sysinfo),
                                                 SYSCALL(ppoll),
                                                 SYSCALL(exit),
                                                 SYSCALL(exit_group),
                                                 SYSCALL(connect),
                                                 SYSCALL(prlimit64)};