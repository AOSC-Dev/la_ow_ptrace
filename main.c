#include <asm-generic/unistd.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <asm-generic/stat.h>
#include <linux/ptrace.h>

#define debug_printf(fmt, ...)                                                 \
  do {                                                                         \
    if (debug_print)                                                           \
      fprintf(debug_file, fmt, __VA_ARGS__);                                   \
  } while (0);

FILE *debug_file;
int debug_print = 0;

long int ptrace_syscall(int child_pid, uint64_t syscall_addr, uint64_t a7,
                        uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                        uint64_t a4, uint64_t a5, uint64_t a6) {
  // read current regs
  struct user_regs_struct regs = {0};
  struct iovec iovec = {.iov_base = &regs, .iov_len = sizeof(regs)};
  ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iovec);

  // override to call our syscall
  struct user_regs_struct temp_regs = {0};
  temp_regs.regs[4] = a0;
  temp_regs.regs[5] = a1;
  temp_regs.regs[6] = a2;
  temp_regs.regs[7] = a3;
  temp_regs.regs[8] = a4;
  temp_regs.regs[9] = a5;
  temp_regs.regs[10] = a6;
  temp_regs.regs[11] = a7;
  temp_regs.csr_era = syscall_addr;

  // set registers and single step
  iovec.iov_base = &temp_regs;
  ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);

  // execute the syscall
  ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);

  // wait for execution finished
  int status;
  waitpid(child_pid, &status, 0);
  assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);

  // read register back to get result
  ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iovec);
  long int result = temp_regs.regs[4];
  debug_printf("Calling syscall_%ld(%lx, %lx, %lx, %lx, %lx, %lx, %lx) = %lx\n",
               a7, a0, a1, a2, a3, a4, a5, a6, result);

  // restore registers
  iovec.iov_base = &regs;
  ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
  return result;
}

void ptrace_read(int child_pid, void *dst, uint64_t src, int length) {
  assert((length % 8) == 0);
  for (int i = 0; i < length; i += 8) {
    uint64_t data = ptrace(PTRACE_PEEKDATA, child_pid, src + i, NULL);
    memcpy(dst + i, &data, (length - i > 8) ? 8 : (length - i));
  }
}

void ptrace_write(int child_pid, uint64_t dst, void *src, int length) {
  assert((length % 8) == 0);
  for (uint64_t i = 0; i < length; i += 8) {
    ptrace(PTRACE_POKEDATA, child_pid, dst + i, ((uint64_t *)src)[i / 8]);
  }
}

struct stat convert_statx_to_stat(struct statx statx) {
  // follow glibc __cp_stat64_statx
  struct stat stat = {0};

  stat.st_dev = ((statx.stx_dev_minor & 0xff) | (statx.stx_dev_major << 8) |
                 ((statx.stx_dev_minor & ~0xff) << 12));
  stat.st_ino = statx.stx_ino;
  stat.st_mode = statx.stx_mode;
  stat.st_nlink = statx.stx_nlink;
  stat.st_uid = statx.stx_uid;
  stat.st_gid = statx.stx_gid;
  stat.st_rdev = ((statx.stx_rdev_minor & 0xff) | (statx.stx_rdev_major << 8) |
                  ((statx.stx_rdev_minor & ~0xff) << 12));
  stat.st_size = statx.stx_size;
  stat.st_blksize = statx.stx_blksize;
  stat.st_blocks = statx.stx_blocks;
  stat.st_atime = statx.stx_atime.tv_sec;
  stat.st_atime_nsec = statx.stx_atime.tv_nsec;
  stat.st_mtime = statx.stx_mtime.tv_sec;
  stat.st_mtime_nsec = statx.stx_mtime.tv_nsec;
  stat.st_ctime = statx.stx_ctime.tv_sec;
  stat.st_ctime_nsec = statx.stx_ctime.tv_nsec;
  return stat;
}

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
                                                 SYSCALL(read),
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
                                                 SYSCALL(rt_sigprocmask),
                                                 SYSCALL(rt_sigaction),
                                                 SYSCALL(rt_sigpending),
                                                 SYSCALL(rt_sigtimedwait),
                                                 SYSCALL(rt_sigsuspend),
                                                 SYSCALL(fcntl),
                                                 SYSCALL(dup),
                                                 SYSCALL(sysinfo),
                                                 SYSCALL(connect),
                                                 SYSCALL(prlimit64)};

int main(int argc, char *argv[]) {
  if (argc == 1) {
    fprintf(stderr, "%s command args...\n", argv[0]);
    return 1;
  }

  debug_file = stderr;
  char *enable_debug = getenv("LA_OW_PTRACE_DEBUG");
  if (enable_debug && strcmp(enable_debug, "1") == 0) {
    // print to stderr
    debug_print = 1;
  } else if (enable_debug) {
    // save to file
    debug_file = fopen(enable_debug, "w");
    if (debug_file) {
      debug_print = 1;
    }
  }

  // Adapted from
  // https://www.alfonsobeato.net/c/filter-and-modify-system-calls-with-seccomp-and-ptrace/
  // https://github.com/alfonsosanchezbeato/ptrace-redirect/blob/master/redirect.c
  pid_t child_pid;
  if ((child_pid = fork()) == 0) {
    // in child
    // allow parent to ptrace me
    ptrace(PTRACE_TRACEME, 0, 0, 0);

    // tell parent we are ready
    kill(getpid(), SIGSTOP);

    // run child process
    int result = execvp(argv[1], &argv[1]);
    perror("execvp");
    return result;
  } else {
    // in parent
    // wait for SIGSTOP
    int status;
    waitpid(child_pid, &status, 0);

    // Set bit 7 in the signal number for syscall traps
    ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD);

    // mmap one page for syscall emulation
    uint64_t mmap_page = 0;

    // capture syscall
    while (1) {
      ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
      waitpid(child_pid, &status, 0);

      // child process exited
      if (WIFEXITED(status))
        return WEXITSTATUS(status);

      // 0x80: see PTRACE_O_TRACESYSGOOD
      if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) {
        // read registers
        struct user_regs_struct regs = {0};
        struct iovec iovec = {.iov_base = &regs, .iov_len = sizeof(regs)};
        ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iovec);

        // see struct user_regs_struct
        // read syscall number from register a7(r11)
        uint64_t syscall = regs.regs[11];
        // read original arguments
        uint64_t orig_a0 = regs.orig_a0;
        uint64_t orig_a1 = regs.regs[5];
        uint64_t orig_a2 = regs.regs[6];
        uint64_t orig_a3 = regs.regs[7];
        // csr_era += 4 in kernel
        uint64_t syscall_addr = regs.csr_era - 4;

        // sizeof(sigset_t) is different: 8 vs 16
        if (syscall == __NR_rt_sigprocmask && orig_a3 == 16) {
          debug_printf("Handling rt_sigprocmask(%ld, %ld, %ld, %ld)\n", orig_a0,
                       orig_a1, orig_a2, orig_a3);
          // clear higher part of old sigset(a2)
          if (orig_a2) {
            ptrace(PTRACE_POKEDATA, child_pid, orig_a2 + 8, 0);
          }

          // override a3 to 8
          regs.regs[7] = 8;
          ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
        } else if (syscall == __NR_rt_sigaction && orig_a3 == 16) {
          debug_printf("Handling rt_sigaction(%ld, %ld, %ld, %ld)\n", orig_a0,
                       orig_a1, orig_a2, orig_a3);
          // clear higher part of old sigset in struct sigaction(a2)
          if (orig_a2) {
            ptrace(PTRACE_POKEDATA, child_pid, orig_a2 + 24, 0);
          }

          // override a3 to 8
          regs.regs[7] = 8;
          ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
        } else if (syscall == __NR_rt_sigpending && orig_a1 == 16) {
          debug_printf("Handling rt_sigpending(%ld, %ld)\n", orig_a0, orig_a1);
          // clear higher part of old sigset in sigset(a0)
          if (orig_a0) {
            ptrace(PTRACE_POKEDATA, child_pid, orig_a0 + 8, 0);
          }

          // override a1 to 8
          regs.regs[5] = 8;
          ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
        } else if (syscall == __NR_rt_sigtimedwait && orig_a3 == 16) {
          debug_printf("Handling rt_sigtimedwait(%ld, %ld, %ld, %ld)\n", orig_a0,
                       orig_a1, orig_a2, orig_a3);
          // override a3 to 8
          regs.regs[7] = 8;
          ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
        } else if (syscall == __NR_rt_sigsuspend && orig_a1 == 16) {
          debug_printf("Handling rt_sigsuspend(%ld, %ld)\n", orig_a0, orig_a1);
          // override a1 to 8
          regs.regs[5] = 8;
          ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
        }

        // trace syscall exit
        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
        waitpid(child_pid, &status, 0);
        // child process exited
        if (WIFEXITED(status))
          return WEXITSTATUS(status);

        // get result
        ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iovec);
        int64_t result = regs.regs[4];

        // minimal strace
        if (syscall_name_table[syscall]) {
          debug_printf("Strace: syscall_%s(%ld, %ld, %ld, %ld) = %ld\n",
                       syscall_name_table[syscall], orig_a0, orig_a1, orig_a2,
                       orig_a3, result);
        } else {
          debug_printf("Strace: syscall_%ld(%ld, %ld, %ld, %ld) = %ld\n", syscall,
                       orig_a0, orig_a1, orig_a2, orig_a3, result);
        }

        if (result == -ENOSYS) {
          debug_printf("Unimplemented syscall by kernel: %ld\n", syscall);

          if (!mmap_page) {
            // create page in child
            mmap_page = ptrace_syscall(child_pid, syscall_addr, __NR_mmap, 0,
                                       16384, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, 0);
            debug_printf("Create page for buffer at %lx(%ld)\n", mmap_page,
                         mmap_page);
          }

          if (syscall == 79) {
            debug_printf("Handling newfstatat(%ld, %lx, %lx, %ld)\n", orig_a0,
                         orig_a1, orig_a2, orig_a3);

            // implementing syscall via statx
            // statx(fd, path,
            // AT_STATX_SYNC_AS_STAT|AT_NO_AUTOMOUNT,
            // STATX_BASIC_STATS, &statx)
            uint64_t result =
                ptrace_syscall(child_pid, syscall_addr, __NR_statx, orig_a0,
                               orig_a1, AT_STATX_SYNC_AS_STAT | AT_NO_AUTOMOUNT,
                               STATX_BASIC_STATS, mmap_page, 0, 0);

            if (result == 0) {
              // success, update buffer from user
              // follow glibc __cp_stat64_statx
              struct statx statx = {0};
              ptrace_read(child_pid, &statx, mmap_page, sizeof(struct statx));

              struct stat stat = convert_statx_to_stat(statx);
              ptrace_write(child_pid, orig_a2, &stat, sizeof(struct stat));
            }

            // pass result to user
            regs.regs[4] = result;
            ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
          } else if (syscall == 80) {
            debug_printf("Handling fstat(%ld, %lx)\n", orig_a0, orig_a1);

            // zero path argument
            uint64_t zero = 0;
            ptrace_write(child_pid, mmap_page, &zero, 8);

            // implementing syscall via statx
            // statx(fd, "",
            // AT_STATX_SYNC_AS_STAT|AT_NO_AUTOMOUNT|AT_EMPTY_PATH,
            // STATX_BASIC_STATS, &statx)
            uint64_t result = ptrace_syscall(
                child_pid, syscall_addr, __NR_statx, orig_a0, mmap_page,
                AT_STATX_SYNC_AS_STAT | AT_NO_AUTOMOUNT | AT_EMPTY_PATH,
                STATX_BASIC_STATS, mmap_page, 0, 0);

            if (result == 0) {
              // success, update buffer from user
              struct statx statx = {0};
              ptrace_read(child_pid, &statx, mmap_page, sizeof(struct statx));

              struct stat stat = convert_statx_to_stat(statx);
              ptrace_write(child_pid, orig_a1, &stat, sizeof(struct stat));
            }

            // pass result to user
            regs.regs[4] = result;
            ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
          }
        }
      } else {
        debug_printf("Unknown status %d\n", status);
      }
    }
  }
  return 0;
}
