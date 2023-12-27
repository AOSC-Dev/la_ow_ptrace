#include <signal.h>
#include <sys/ucontext.h>

struct ow_sigset_t {
  unsigned long sig[2];
};

struct ow_mcontext_t {
  unsigned long long pc;
  unsigned long long gregs[32];
  unsigned int flags;
  unsigned int fcsr;
  unsigned int vcsr;
  unsigned long long fcc;
  unsigned long long scr[4];
  union {
    unsigned int val32[8];
    unsigned long long val64[4];
  } sc_fpregs[32] __attribute__((aligned(32)));
  unsigned char reserved[4096] __attribute__((__aligned__(16)));
};

struct ow_ucontext_t {
  unsigned long int flags;
  struct ow_ucontext_t *link;
  stack_t stack;
  struct ow_mcontext_t mcontext;
  struct ow_sigset_t sigmask;
};

void signal_handler(int sig, siginfo_t *siginfo, void *ucontext, void (*real_signal_handler)(int sig, siginfo_t *siginfo, void *ucontext)) {
  ucontext_t *uc = (ucontext_t *)ucontext;
  struct ow_ucontext_t ow_uc;

  // convert ucontext to old world
  ow_uc.flags = uc->__uc_flags;
  ow_uc.link = NULL; // TODO
  ow_uc.stack = uc->uc_stack;
  // location of sigmask has changed
  ow_uc.sigmask.sig[0] = uc->uc_sigmask.__val[0];

  ow_uc.mcontext.pc = uc->uc_mcontext.__pc;
  for (int i = 0; i < 32; i++)
    ow_uc.mcontext.gregs[i] = uc->uc_mcontext.__gregs[i];
  ow_uc.mcontext.flags = uc->uc_mcontext.__flags;

  // TODO: fp

  real_signal_handler(sig, siginfo, &ow_uc);

  // convert ucontext to new world
  uc->__uc_flags = ow_uc.flags;
  uc->uc_link = NULL; // TODO
  uc->uc_stack = ow_uc.stack;
  uc->uc_sigmask.__val[0] = ow_uc.sigmask.sig[0];

  uc->uc_mcontext.__pc = ow_uc.mcontext.pc;
  for (int i = 0; i < 32; i++)
    uc->uc_mcontext.__gregs[i] = ow_uc.mcontext.gregs[i];
  uc->uc_mcontext.__flags = ow_uc.mcontext.flags;
}