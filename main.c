#include <elf.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>

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

    // capture syscall
    while (1) {
      ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
      waitpid(child_pid, &status, 0);

      // child process exited
      if (WIFEXITED(status))
        break;

      // 0x80: see PTRACE_O_TRACESYSGOOD
      if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) {
        // read syscall number from register a7(r11)
        // see struct user_regs_struct
        struct user_regs_struct regs = {0};
        struct iovec iovec = {.iov_base = &regs, .iov_len = sizeof(regs)};
        ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iovec);
        int syscall = regs.regs[11];

        if (syscall == 79) {
          fprintf(stderr, "Handling newfstatat\n");

          // changing syscall to statx
        } else if (syscall == 80) {
          fprintf(stderr, "Handling fstat\n");

          // changing syscall to statx
        }

        // trace syscall exit
        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
        waitpid(child_pid, &status, 0);

        // get result
        ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iovec);
        int result = regs.regs[4];
        if (result == -ENOSYS) {
          fprintf(stderr, "Unimplemented syscall by kernel: %d\n", syscall);
        }
      }
    }
  }
  return 0;
}
