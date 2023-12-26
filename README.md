# LoongArch Old World Compatiblity with PTrace

You can try [Linux kernel module for compatibility with LoongArch's old-world ABI ](https://github.com/AOSC-Dev/la_ow_syscall) for a more mature solution.

This project aims to implement old-world compatibility in a purely userspace manner. The performance can be worse than the kernel-space approach, but it is easier to integrate with distributions.

## Usage

Compile `la_ow_ptrace` and run applications with it:

```shell
mkdir build
cd build
cmake ..
make
./la_ow_ptrace /path/to/ow/binary
```

You can set environment variable `LA_OW_PTRACE_DEBUG=1` to enable debug logs.

## Progress

- [x] fstat/newfstatat
- [x] rt_sigprocmask/rt_sigaction/rt_sigpending/rt_sigtimedwait/rt_sigsuspend
- [x] handle child process
- [ ] getrlimit/setrlimit
- [ ] pselect6/ppoll
- [ ] epoll_pwait/epoll_pwait2
