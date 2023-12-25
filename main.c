#include <asm-generic/unistd.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/ptrace.h>

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

  // restore registers
  iovec.iov_base = &regs;
  ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iovec);
  return result;
}

int main(int argc, char *argv[]) {
  if (argc == 1) {
    fprintf(stderr, "%s command args...\n", argv[0]);
    return 1;
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
    return execvp(argv[1], &argv[1]);
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
        break;

      // 0x80: see PTRACE_O_TRACESYSGOOD
      if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) {
        // read registers
        struct user_regs_struct regs = {0};
        struct iovec iovec = {.iov_base = &regs, .iov_len = sizeof(regs)};
        ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iovec);

        // see struct user_regs_struct
        // read syscall number from register a7(r11)
        int syscall = regs.regs[11];
        // read first argument
        int orig_a0 = regs.orig_a0;
        // csr_era += 4 in kernel
        uint64_t syscall_addr = regs.csr_era - 4;

        // trace syscall exit
        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
        waitpid(child_pid, &status, 0);

        // get result
        ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iovec);
        int result = regs.regs[4];
        if (result == -ENOSYS) {
          fprintf(stderr, "Unimplemented syscall by kernel: %d\n", syscall);

          if (!mmap_page) {
            // create page in child
            mmap_page = ptrace_syscall(
                child_pid, syscall_addr, __NR_mmap, 0, 16384,
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, 0);
            fprintf(stderr, "mmap-ed %lx(%ld)\n", mmap_page, mmap_page);
          }

          if (syscall == 79) {
            fprintf(stderr, "Handling newfstatat\n");

          } else if (syscall == 80) {
            fprintf(stderr, "Handling fstat\n");

            // implementing syscall via statx
            // statx(fd, "",
            // AT_STATX_SYNC_AS_STAT|AT_NO_AUTOMOUNT|AT_EMPTY_PATH,
            // STATX_BASIC_STATS, &statx)
            uint64_t result = ptrace_syscall(
                child_pid, syscall_addr, __NR_statx, orig_a0, mmap_page,
                AT_STATX_SYNC_AS_STAT | AT_NO_AUTOMOUNT | AT_EMPTY_PATH,
                STATX_BASIC_STATS, mmap_page, 0, 0);
            fprintf(stderr, "statx got %lx(%ld)\n", result, result);
          }
        }
      } else {
        fprintf(stderr, "Unknown status %d\n", status);
      }
    }
  }
  return 0;
}
