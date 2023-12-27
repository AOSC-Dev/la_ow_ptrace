#include <asm-generic/unistd.h>
#include <assert.h>
#include <csignal>
#include <cstdint>
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

#include <map>

#include "common.h"

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
  assert(ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iovec) == 0);

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
  assert(ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec) == 0);

  // execute the syscall
  assert(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) == 0);

  // wait for execution finished
  int status;
  waitpid(child_pid, &status, 0);
  assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);

  // read register back to get result
  assert(ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iovec) == 0);
  long int result = temp_regs.regs[4];
  debug_printf("[%d] Invoking in child syscall_%ld(%lx, %lx, %lx, %lx, %lx, "
               "%lx, %lx) = %lx\n",
               child_pid, a7, a0, a1, a2, a3, a4, a5, a6, result);

  // restore registers
  iovec.iov_base = &regs;
  assert(ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec) == 0);
  return result;
}

void ptrace_read(int child_pid, void *dst, uint64_t src, int length) {
  assert((length % 8) == 0);
  for (int i = 0; i < length; i += 8) {
    errno = 0;
    uint64_t data = ptrace(PTRACE_PEEKDATA, child_pid, src + i, NULL);
    assert(errno == 0);
    memcpy((uint8_t *)dst + i, &data, (length - i > 8) ? 8 : (length - i));
  }
}

void ptrace_write(int child_pid, uint64_t dst, void *src, int length) {
  assert((length % 8) == 0);
  for (uint64_t i = 0; i < length; i += 8) {
    errno = 0;
    ptrace(PTRACE_POKEDATA, child_pid, dst + i, ((uint64_t *)src)[i / 8]);
    assert(errno == 0);
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

// record the state of each tracee
struct trace_state {
  // buffer in child process
  uint64_t mmap_page;
  // this is syscall exit
  bool is_syscall_exit;

  // revert pselect6 size change
  bool revert_pselect6 = false;
};

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
    assert(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);

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

    // PTRACE_O_TRACESYSGOOD: Set bit 7 in the signal number for syscall traps
    // PTRACE_O_TRACEFORK: Trace forked process
    ptrace(PTRACE_SETOPTIONS, child_pid, 0,
           PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE |
               PTRACE_O_TRACEVFORK);

    // maintain state for each tracee
    std::map<pid_t, trace_state> states;

    // there can be multiple children! record the first child
    pid_t first_child_pid = child_pid;

    // inject signal to child process
    int inject_signal = 0;

    // capture syscall
    while (1) {
      ptrace(PTRACE_SYSCALL, child_pid, 0, inject_signal);
      inject_signal = 0;
      child_pid = waitpid(-1, &status, 0);
      assert(child_pid > 0);

      // child process exited
      if (WIFEXITED(status)) {
        if (child_pid == first_child_pid) {
          // propagate exit status
          return WEXITSTATUS(status);
        } else {
          continue;
        }
      }

      if (WIFSTOPPED(status)) {
        // ptrace-stopped

        // 0x80: see PTRACE_O_TRACESYSGOOD
        if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
          trace_state &cur = states[child_pid];

          // read registers
          struct user_regs_struct regs = {0};
          struct iovec iovec = {.iov_base = &regs, .iov_len = sizeof(regs)};
          assert(ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iovec) == 0);

          // see struct user_regs_struct
          // read syscall number from register a7(r11)
          uint64_t syscall = regs.regs[11];
          // read original arguments
          uint64_t orig_a0 = regs.orig_a0;
          uint64_t orig_a1 = regs.regs[5];
          uint64_t orig_a2 = regs.regs[6];
          uint64_t orig_a3 = regs.regs[7];
          uint64_t orig_a4 = regs.regs[8];
          uint64_t orig_a5 = regs.regs[9];
          // csr_era += 4 in kernel
          uint64_t syscall_addr = regs.csr_era - 4;

          if (cur.is_syscall_exit) {
            // syscall exit

            if (cur.revert_pselect6) {
              // revert size to 16
              assert(ptrace(PTRACE_POKEDATA, child_pid, orig_a5 + 8, 16) == 0);
            }

            // get result
            int64_t result = regs.regs[4];

            // minimal strace
            if (syscall_name_table[syscall]) {
              debug_printf("[%d] Strace: syscall_%s(%ld, %ld, %ld, %ld, %ld, "
                           "%ld) = %ld\n",
                           child_pid, syscall_name_table[syscall], orig_a0,
                           orig_a1, orig_a2, orig_a3, orig_a4, orig_a5, result);
            } else {
              debug_printf("[%d] Strace: syscall_%ld(%ld, %ld, %ld, %ld, %ld, "
                           "%ld) = %ld\n",
                           child_pid, syscall, orig_a0, orig_a1, orig_a2,
                           orig_a3, orig_a4, orig_a5, result);
            }
            if (syscall == __NR_faccessat || syscall == __NR_openat ||
                syscall == __NR_statx || syscall == __NR_readlinkat ||
                syscall == 79) {
              char buffer[256] = {0};
              ptrace_read(child_pid, buffer, orig_a1, 128);
              debug_printf("[%d] Strace: file path is %s\n", child_pid, buffer);
            }

            if (!cur.mmap_page && syscall != __NR_execve) {
              // create page in child
              uint64_t mmap_page =
                  ptrace_syscall(child_pid, syscall_addr, __NR_mmap, 0, 16384,
                                 PROT_READ | PROT_WRITE | PROT_EXEC,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, 0);
              debug_printf("[%d] Create page for buffer at %lx(%ld)\n",
                           child_pid, mmap_page, mmap_page);
              cur.mmap_page = mmap_page;
            }

            if (result == -ENOSYS) {
              debug_printf("[%d] Unimplemented syscall by kernel: %ld(%s)\n",
                           child_pid, syscall, syscall_name_table[syscall]);
              uint64_t mmap_page = cur.mmap_page;

              if (syscall == 79) {
                debug_printf("[%d] Handling newfstatat(%ld, %lx, %lx, %ld)\n",
                             child_pid, orig_a0, orig_a1, orig_a2, orig_a3);

                // implementing syscall via statx
                // follow glibc fstatat64_time64_statx
                // statx(fd, path,
                // AT_NO_AUTOMOUNT|flag,
                // STATX_BASIC_STATS, &statx)
                uint64_t result =
                    ptrace_syscall(child_pid, syscall_addr, __NR_statx, orig_a0,
                                   orig_a1, AT_NO_AUTOMOUNT | orig_a3,
                                   STATX_BASIC_STATS, mmap_page, 0, 0);

                if (result == 0) {
                  // success, update buffer from user
                  // follow glibc __cp_stat64_statx
                  struct statx statx = {0};
                  ptrace_read(child_pid, &statx, mmap_page,
                              sizeof(struct statx));

                  struct stat stat = convert_statx_to_stat(statx);
                  ptrace_write(child_pid, orig_a2, &stat, sizeof(struct stat));
                }

                // pass result to user
                regs.regs[4] = result;
                ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
              } else if (syscall == 80) {
                debug_printf("[%d] Handling newfstat(%ld, %lx)\n", child_pid,
                             orig_a0, orig_a1);

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
                  ptrace_read(child_pid, &statx, mmap_page,
                              sizeof(struct statx));

                  struct stat stat = convert_statx_to_stat(statx);
                  ptrace_write(child_pid, orig_a1, &stat, sizeof(struct stat));
                }

                // pass result to user
                regs.regs[4] = result;
                ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
              }
            }
          } else {
            // syscall enter
            // sizeof(sigset_t) is different: 8 vs 16
            if (syscall == __NR_rt_sigprocmask && orig_a3 == 16) {
              debug_printf("[%d] Handling rt_sigprocmask(%ld, %ld, %ld, %ld)\n",
                           child_pid, orig_a0, orig_a1, orig_a2, orig_a3);
              // clear higher part of old sigset(a2)
              if (orig_a2) {
                ptrace(PTRACE_POKEDATA, child_pid, orig_a2 + 8, 0);
              }

              // override a3 to 8
              regs.regs[7] = 8;
              ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
            } else if (syscall == __NR_rt_sigaction && orig_a3 == 16) {
              debug_printf("[%d] Handling rt_sigaction(%ld, %ld, %ld, %ld)\n",
                           child_pid, orig_a0, orig_a1, orig_a2, orig_a3);
              // clear higher part of old sigset in struct sigaction(a2)
              if (orig_a2) {
                ptrace(PTRACE_POKEDATA, child_pid, orig_a2 + 24, 0);
              }

              if (orig_a1) {
                // find user's real sigaction handler
                uint64_t sigaction =
                    ptrace(PTRACE_PEEKDATA, child_pid, orig_a1, 0);
                if (sigaction) {
                  // generate wrapper for sigaction handler
                  // see signal_handler.s
                  uint32_t code[] = {
                      0x02e8c063, // 	addi.d      	$sp, $sp, -1488
                      0x29d72061, // 	st.d        	$ra, $sp, 1480
                      0x29d70077, // 	st.d        	$s0, $sp, 1472
                      0x29d6e078, // 	st.d        	$s1, $sp, 1464
                      0x29d6c079, // 	st.d        	$s2, $sp, 1456
                      0x15ffffed, // 	lu12i.w     	$t1, -1
                      0x0010b463, // 	add.d       	$sp, $sp, $t1
                      0x001500d9, // 	move        	$s2, $a2
                      0x15ffffd7, // 	lu12i.w     	$s0, -2
                      0x03a9bef7, // 	ori         	$s0, $s0, 0xa6f
                      0x1400002c, // 	lu12i.w     	$t0, 1
                      0x0396c18c, // 	ori         	$t0, $t0, 0x5b0
                      0x0010dd8c, // 	add.d       	$t0, $t0, $s0
                      0x00108d97, // 	add.d       	$s0, $t0, $sp
                      0x004516f7, // 	srli.d      	$s0, $s0, 0x5
                      0x004116f7, // 	slli.d      	$s0, $s0, 0x5
                      0x260000cc, // 	ldptr.d     	$t0, $a2, 0
                      0x270002ec, // 	stptr.d     	$t0, $s0, 0
                      0x29c022e0, // 	st.d        	$zero, $s0, 8
                      0x28c040cc, // 	ld.d        	$t0, $a2, 16
                      0x29c042ec, // 	st.d        	$t0, $s0, 16
                      0x28c060cc, // 	ld.d        	$t0, $a2, 24
                      0x29c062ec, // 	st.d        	$t0, $s0, 24
                      0x28c080cc, // 	ld.d        	$t0, $a2, 32
                      0x29c082ec, // 	st.d        	$t0, $s0, 32
                      0x28c0a0cc, // 	ld.d        	$t0, $a2, 40
                      0x271582ec, // 	stptr.d     	$t0, $s0, 5504
                      0x28c2c0cc, // 	ld.d        	$t0, $a2, 176
                      0x29c102ec, // 	st.d        	$t0, $s0, 64
                      0x0015000c, // 	move        	$t0, $zero
                      0x02c2e0d8, // 	addi.d      	$s1, $a2, 184
                      0x0284000f, // 	li.w        	$t3, 256

                      // .L2
                      0x0010b2ed, // 	add.d       	$t1, $s0, $t0
                      0x380c330e, // 	ldx.d       	$t2, $s1, $t0
                      0x29c121ae, // 	st.d        	$t2, $t1, 72
                      0x02c0218c, // 	addi.d      	$t0, $t0, 8
                      0x5ffff18f, // 	bne         	$t0, $t3, -16	# 80

                      0x2401bb2c, // 	ldptr.w     	$t0, $s2, 440
                      0x298522ec, // 	st.w        	$t0, $s0, 328

                      // load real signal handler address
                      0x1400000c, // 	lu12i.w     	$t0, 0
                      0x0380018c, // 	ori         	$t0, $t0, 0x0
                      0x1600000c, // 	lu32i.d     	$t0, 0
                      0x0300018c, // 	lu52i.d     	$t0, $t0, 0

                      0x001502e6, // 	move        	$a2, $s0
                      0x4c000181, // 	jirl        	$ra, $t0, 0
                      0x260002ec, // 	ldptr.d     	$t0, $s0, 0
                      0x2700032c, // 	stptr.d     	$t0, $s2, 0
                      0x29c02320, // 	st.d        	$zero, $s2, 8
                      0x28c042ec, // 	ld.d        	$t0, $s0, 16
                      0x29c0432c, // 	st.d        	$t0, $s2, 16
                      0x28c062ec, // 	ld.d        	$t0, $s0, 24
                      0x29c0632c, // 	st.d        	$t0, $s2, 24
                      0x28c082ec, // 	ld.d        	$t0, $s0, 32
                      0x29c0832c, // 	st.d        	$t0, $s2, 32
                      0x261582ec, // 	ldptr.d     	$t0, $s0, 5504
                      0x29c0a32c, // 	st.d        	$t0, $s2, 40
                      0x28c102ec, // 	ld.d        	$t0, $s0, 64
                      0x29c2c32c, // 	st.d        	$t0, $s2, 176
                      0x0015000c, // 	move        	$t0, $zero
                      0x0284000e, // 	li.w        	$t2, 256

                      // .L3
                      0x0010b2ed, // 	add.d       	$t1, $s0, $t0
                      0x28c121ad, // 	ld.d        	$t1, $t1, 72
                      0x381c330d, // 	stx.d       	$t1, $s1, $t0
                      0x02c0218c, // 	addi.d      	$t0, $t0, 8
                      0x5ffff18e, // 	bne         	$t0, $t2, -16	# f0

                      0x24014aec, // 	ldptr.w     	$t0, $s0, 328
                      0x2986e32c, // 	st.w        	$t0, $s2, 440
                      0x1400002d, // 	lu12i.w     	$t1, 1
                      0x0010b463, // 	add.d       	$sp, $sp, $t1
                      0x28d72061, // 	ld.d        	$ra, $sp, 1480
                      0x28d70077, // 	ld.d        	$s0, $sp, 1472
                      0x28d6e078, // 	ld.d        	$s1, $sp, 1464
                      0x28d6c079, // 	ld.d        	$s2, $sp, 1456
                      0x02d74063, // 	addi.d      	$sp, $sp, 1488
                      0x4c000020, // 	ret
                      0x00000000  // padding
                  };

                  // fill address into assembly
                  // lu12i.w
                  uint64_t abs_hi20 = (sigaction & 0xFFFFFFFF) >> 12;
                  code[39] |= abs_hi20 << 5;
                  // ori
                  uint64_t abs_lo12 = sigaction & 0xFFF;
                  code[40] |= abs_lo12 << 10;
                  // lu32i.d
                  uint64_t abs64_lo20 = (sigaction >> 32) & 0xFFFFF;
                  code[41] |= abs64_lo20 << 5;
                  // lu52i.d
                  uint64_t abs64_hi12 = sigaction >> 52;
                  code[42] |= abs64_hi12 << 10;

                  // copy code to somewhere in mmap_page
                  uint64_t fake_signal_handler = cur.mmap_page + 4096;
                  ptrace_write(child_pid, fake_signal_handler, code,
                               sizeof(code));

                  // override sigaction
                  debug_printf("[%d] Replacing sigaction handler %lx to %lx\n",
                               child_pid, sigaction, fake_signal_handler);
                  ptrace(PTRACE_POKEDATA, child_pid, orig_a1,
                         fake_signal_handler);
                }
              }

              // override a3 to 8
              regs.regs[7] = 8;
              ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
            } else if (syscall == __NR_rt_sigpending && orig_a1 == 16) {
              debug_printf("[%d] Handling rt_sigpending(%ld, %ld)\n", child_pid,
                           orig_a0, orig_a1);
              // clear higher part of old sigset in sigset(a0)
              if (orig_a0) {
                ptrace(PTRACE_POKEDATA, child_pid, orig_a0 + 8, 0);
              }

              // override a1 to 8
              regs.regs[5] = 8;
              ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
            } else if (syscall == __NR_rt_sigtimedwait && orig_a3 == 16) {
              debug_printf(
                  "[%d] Handling rt_sigtimedwait(%ld, %ld, %ld, %ld)\n",
                  child_pid, orig_a0, orig_a1, orig_a2, orig_a3);
              // override a3 to 8
              regs.regs[7] = 8;
              ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
            } else if (syscall == __NR_rt_sigsuspend && orig_a1 == 16) {
              debug_printf("[%d] Handling rt_sigsuspend(%ld, %ld)\n", child_pid,
                           orig_a0, orig_a1);
              // override a1 to 8
              regs.regs[5] = 8;
              ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
            } else if (syscall == __NR_ppoll && orig_a4 == 16) {
              debug_printf("[%d] Handling ppoll(%ld, %ld, %ld, %ld, %ld)\n",
                           child_pid, orig_a0, orig_a1, orig_a2, orig_a3,
                           orig_a4);
              // override a4 to 8
              regs.regs[8] = 8;
              ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
            } else if (syscall == __NR_pselect6 && orig_a5) {
              debug_printf(
                  "[%d] Handling pselect6(%ld, %ld, %ld, %ld, %ld, %ld)\n",
                  child_pid, orig_a0, orig_a1, orig_a2, orig_a3, orig_a4,
                  orig_a5);
              // a5 points to struct sigset_argpack
              // read size field
              uint64_t size =
                  ptrace(PTRACE_PEEKDATA, child_pid, orig_a5 + 8, NULL);
              if (size == 16) {
                // override size to 8
                ptrace(PTRACE_POKEDATA, child_pid, orig_a5 + 8, 8);
                cur.revert_pselect6 = true;
              }
            } else if (syscall == __NR_epoll_pwait && orig_a5 == 16) {
              debug_printf(
                  "[%d] Handling epoll_pwait(%ld, %ld, %ld, %ld, %ld, %ld)\n",
                  child_pid, orig_a0, orig_a1, orig_a2, orig_a3, orig_a4,
                  orig_a5);
              // override a5 to 8
              regs.regs[9] = 8;
              ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
            } else if (syscall == __NR_epoll_pwait2 && orig_a5 == 16) {
              debug_printf("[%d] Handling epoll_pwait2(%ld, %ld, %ld, %ld, "
                           "%ld, %ld)\n",
                           child_pid, orig_a0, orig_a1, orig_a2, orig_a3,
                           orig_a4, orig_a5);
              // override a5 to 8
              regs.regs[9] = 8;
              ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
            } else if (syscall == __NR_signalfd4 && orig_a2 == 16) {
              debug_printf("[%d] Handling signalfd4(%ld, %ld, %ld, %ld)\n",
                           child_pid, orig_a0, orig_a1, orig_a2, orig_a3);
              // override a2 to 8
              regs.regs[6] = 8;
              ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
            } else if (syscall == __NR_execve) {
              // mmap-ed page is invalidated
              cur.mmap_page = 0;
            }
          }
          cur.is_syscall_exit = !cur.is_syscall_exit;
          continue;
        } else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
          debug_printf("[%d] Child fork (PTRACE_EVENT_FORK)\n", child_pid);
          continue;
        } else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
          debug_printf("[%d] Child vfork (PTRACE_EVENT_VFORK)\n", child_pid);
          continue;
        } else if ((status >> 8) ==
                   (SIGTRAP | (PTRACE_EVENT_VFORK_DONE << 8))) {
          debug_printf("[%d] Child vfork done (PTRACE_EVENT_VFORK_DONE)\n",
                       child_pid);
          continue;
        } else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
          debug_printf("[%d] Child clone (PTRACE_EVENT_CLONE)\n", child_pid);
          continue;
        } else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
          debug_printf("[%d] Child exec (PTRACE_EVENT_EXEC)\n", child_pid);
          continue;
        } else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
          debug_printf("[%d] Child exit (PTRACE_EVENT_EXIT)\n", child_pid);
          continue;
        } else if ((status >> 8) == SIGTRAP) {
          // man 2 ptrace:
          // "If the PTRACE_O_TRACEEXEC option is not in effect, all successful
          // calls to execve(2) by the traced process will cause it to be sent
          // a SIGTRAP signal, giving the parent a chance to gain control
          // before the new program begins execution."
          debug_printf("[%d] Child got SIGTRAP\n", child_pid);
          continue;
        } else if ((status >> 8) == SIGSTOP) {
          debug_printf("[%d] Child got SIGSTOP\n", child_pid);
          continue;
        } else if ((status >> 8) == SIGCHLD) {
          debug_printf("[%d] Child got SIGCHLD\n", child_pid);
          inject_signal = SIGCHLD;
          continue;
        } else if ((status >> 8) == SIGINT) {
          debug_printf("[%d] Child got SIGINT\n", child_pid);
          inject_signal = SIGINT;
          continue;
        } else if ((status >> 8) == SIGWINCH) {
          debug_printf("[%d] Child got SIGWINCH\n", child_pid);
          inject_signal = SIGWINCH;
          continue;
        } else if ((status >> 8) == SIGUSR1) {
          debug_printf("[%d] Child got SIGUSR1\n", child_pid);
          inject_signal = SIGUSR1;
          continue;
        }
      }

      debug_printf("[%d] Unknown status %d\n", child_pid, status);
    }
  }
  return 0;
}
