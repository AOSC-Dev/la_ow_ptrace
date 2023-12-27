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
  printf("sp = %lx\n", sp);

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

#if NSIG == 64 + 1
  // new world
  struct sctx_info *sctx = (struct sctx_info *)uc->uc_mcontext.__extcontext;
  while (sctx->magic != 0) {
    printf("sctx entry: magic=0x%x, size=%d\n", sctx->magic, sctx->size);
    if (sctx->magic == LASX_CTX_MAGIC) {
      struct lasx_context *ctx =
          (struct lasx_context *)((uint8_t *)sctx + sizeof(struct sctx_info));
      for (int i = 0; i < 32; i++)
        printf("lasx_context[%d] = %llx %llx %llx %llx\n", i, ctx->regs[4 * i],
               ctx->regs[4 * i + 1], ctx->regs[4 * i + 2],
               ctx->regs[4 * i + 3]);
      printf("fcc = %lld\n", ctx->fcc);
      printf("fcsr = %d\n", ctx->fcsr);
    }
    sctx = (struct sctx_info *)((uint8_t *)sctx + sctx->size);
  }
#else
  // old world
  // there is a mismatch between sigcontext and mcontext with regard to sc_scr!?
  struct sigcontext *sc = (struct sigcontext *)&uc->uc_mcontext;
  printf("ucontext->uc_mcontext.__fcsr = %d\n", uc->uc_mcontext.__fcsr);
  printf("ucontext->uc_mcontext.__vcsr = %d\n", uc->uc_mcontext.__vcsr);
  printf("ucontext->uc_mcontext.__fcc = %lld\n", uc->uc_mcontext.__fcc);

  // different!
  for (int i = 0; i < 4; i++)
    printf("ucontext->uc_mcontext.__scr[%d] = %lld\n", i, sc->sc_scr[i]);
  for (int i = 0; i < 32; i++)
    printf("ucontext->uc_mcontext.__fpregs[%d].__val64 = %llx %llx %llx %llx\n",
           i, sc->sc_fpregs[i].val64[0], sc->sc_fpregs[i].val64[1],
           sc->sc_fpregs[i].val64[2], sc->sc_fpregs[i].val64[3]);
  printf("ucontext->uc_mcontext.__reserved = %lld\n",
         uc->uc_mcontext.__reserved);
#endif
}

int main() {
  struct sigaction new_act;
  struct sigaction old_act;
  memset(&new_act, 0, sizeof(new_act));
  new_act.sa_flags = SA_SIGINFO;
  new_act.sa_sigaction = signal_handler;
  printf("before: signal handler is %p\n", new_act.sa_sigaction);
  sigaction(SIGUSR1, &new_act, &old_act);
  printf("after: signal handler is %p\n", new_act.sa_sigaction);

  // setup some registers, hopefully they appear in ucontext
  register int s0 asm("s0") = 0x11111111;
  register int s1 asm("s1") = 0x22222222;
  register int s2 asm("s2") = 0x33333333;
  register int s3 asm("s3") = 0x44444444;
  register int s4 asm("s4") = 0x55555555;
  register int s5 asm("s5") = 0x66666666;
  register int s6 asm("s6") = 0x77777777;
  register int s7 asm("s7") = 0x88888888;
  register int s8 asm("s8") = 0x99999999;

  register double f0 asm("f0") = 0.0;
  register double f1 asm("f1") = 1.0;
  register double f2 asm("f2") = 2.0;
  register double f3 asm("f3") = 3.0;
  register double f4 asm("f4") = 4.0;
  register double f5 asm("f5") = 5.0;
  register double f6 asm("f6") = 6.0;
  register double f7 asm("f7") = 7.0;
  register double f8 asm("f8") = 8.0;
  register double f9 asm("f9") = 9.0;

  // manually set
  asm volatile("xvrepli.d $xr10, 0");
  asm volatile("xvrepli.d $xr11, 1");
  asm volatile("xvrepli.d $xr12, 2");
  asm volatile("xvrepli.d $xr13, 3");

  register double f28 asm("f28") = 28.0;
  register double f29 asm("f29") = 29.0;
  register double f30 asm("f30") = 30.0;
  register double f31 asm("f31") = 31.0;

  kill(getpid(), SIGUSR1);

  printf("f0=%f\n", f0);
  printf("f1=%f\n", f1);
  printf("f2=%f\n", f2);
  printf("f3=%f\n", f3);
  printf("f4=%f\n", f4);
  printf("f5=%f\n", f5);
  printf("f6=%f\n", f6);
  printf("f7=%f\n", f7);
  printf("f30=%f\n", f30);
  printf("f31=%f\n", f31);
  return 0;
}
