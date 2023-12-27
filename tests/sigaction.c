#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

void signal_handler(int sig, siginfo_t *siginfo, void *ucontext) {
  // we are sending signals ourselves, so we can use printf!
  printf("Caught signal %d\n", sig);
  printf("siginfo = %p\n", siginfo);
  printf("ucontext = %p\n", ucontext);
  uint64_t sp;
  asm volatile("move %0, $sp" : "=r"(sp));
  printf("sp = %ld\n", sp);

  printf("siginfo->si_signo = %d\n", siginfo->si_signo);
  printf("siginfo->si_code = %d\n", siginfo->si_code);
  printf("siginfo->si_errno = %d\n", siginfo->si_errno);
  printf("siginfo->si_pid = %d\n", siginfo->si_pid);
  printf("siginfo->si_uid = %d\n", siginfo->si_uid);
  printf("siginfo->si_addr = %p\n", siginfo->si_addr);
  printf("siginfo->si_status = %d\n", siginfo->si_status);

  ucontext_t *uc = (ucontext_t *)ucontext;
  printf("ucontext->__uc_flags = %ld\n", uc->__uc_flags);
  printf("ucontext->uc_link = %p\n", uc->uc_link);
  printf("ucontext->uc_stack.ss_sp = %p\n", uc->uc_stack.ss_sp);
  printf("ucontext->uc_stack.ss_flags = %d\n", uc->uc_stack.ss_flags);
  printf("ucontext->uc_stack.ss_size = %ld\n", uc->uc_stack.ss_size);
  printf("ucontext->uc_sigmask[0] = %ld\n", uc->uc_sigmask.__val[0]);
  printf("ucontext->uc_sigmask[1] = %ld\n", uc->uc_sigmask.__val[1]);
  printf("ucontext->uc_mcontext.__pc = %lld\n", uc->uc_mcontext.__pc);
  for (int i = 0; i < 32; i++)
    printf("ucontext->uc_mcontext.__gregs[%d] = %llx\n", i,
           uc->uc_mcontext.__gregs[i]);
  printf("ucontext->uc_mcontext.__flags = %d\n", uc->uc_mcontext.__flags);

  struct sctx_info *sctx = (struct sctx_info *)uc->uc_mcontext.__extcontext;
  while (sctx->magic != 0) {
    printf("sctx entry: magic=0x%x, size=%d\n", sctx->magic, sctx->size);
    sctx = (struct sctx_info *)((uint8_t *)sctx + sctx->size);
  }
}

int main() {
  struct sigaction new_act;
  struct sigaction old_act;
  memset(&new_act, 0, sizeof(new_act));
  new_act.sa_flags = SA_SIGINFO;
  new_act.sa_sigaction = signal_handler;
  sigaction(SIGUSR1, &new_act, &old_act);
  kill(getpid(), SIGUSR1);
  return 0;
}
