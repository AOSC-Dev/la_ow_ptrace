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
./la_ow /path/to/ow/binary
```

You can set environment variable `LA_OW_PTRACE_DEBUG=1` to enable debug logs.

## How does it work

It intercepts syscall from child process. When it met unimplemented old-world-only syscall, it calls the equivalent new-work syscall in child process and converts the result. For syscall where sigset is used, the size is changed from 16 to 8.

## Progress

- [x] newfstat/newfstatat
- [x] rt_sigprocmask/rt_sigaction/rt_sigpending/rt_sigtimedwait/rt_sigsuspend
- [x] pselect6/ppoll
- [x] epoll_pwait/epoll_pwait2
- [x] handle child process
- [x] signalfd4
- [ ] getrlimit/setrlimit

## How to run WPS

1. Install libLOL from AOSC OS
2. Install WPS Office dpkg
3. Run WPS Office with `la_ow`: `./la_ow /opt/kingsoft/wps-office/office6/wps`

## How to run Lbrowser(Loongson Browser)

1. Install libLOL from AOSC OS
2. Install Lbrowser dpkg
3. Run Lbrowser with `la_ow`: `./la_ow /opt/apps/lbrowser/lbrowser --no-sandbox`
