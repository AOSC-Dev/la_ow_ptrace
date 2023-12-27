// compare old & new world signal context
// ucontext: the order of uc_sigmask and uc_mcontext swapped
// sigcontext: fields after sc_flags are different

// old world

// /usr/include/loongarch64-linux-gnu/bits/sigcontext.h

#define FPU_REG_WIDTH 256
#define FPU_ALIGN __attribute__((aligned(32)))

struct sigcontext {
  unsigned long long sc_pc;
  unsigned long long sc_regs[32];
  unsigned int sc_flags;

  unsigned int sc_fcsr;
  unsigned int sc_vcsr;
  unsigned long long sc_fcc;

  unsigned long long sc_scr[4];

  union {
    unsigned int val32[FPU_REG_WIDTH / 32];
    unsigned long long val64[FPU_REG_WIDTH / 64];
  } sc_fpregs[32] FPU_ALIGN;
  unsigned char sc_reserved[4096] __attribute__((__aligned__(16)));
};

union __loongarch_mc_fp_state {
  unsigned int __val32[256 / 32];
  unsigned long long __val64[256 / 64];
};

// /usr/include/loongarch64-linux-gnu/sys/ucontext.h

typedef struct mcontext_t {
  unsigned long long __pc;
  unsigned long long __gregs[32];
  unsigned int __flags;

  unsigned int __fcsr;
  unsigned int __vcsr;
  unsigned long long __fcc;
  union __loongarch_mc_fp_state __fpregs[32] __attribute__((__aligned__(32)));

  unsigned int __reserved;
} mcontext_t;

/* Userlevel context.  */
typedef struct ucontext_t {
  unsigned long int __uc_flags;
  struct ucontext_t *uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  sigset_t uc_sigmask;
} ucontext_t;

// new world

// /usr/include/asm/sigcontext.h

struct sigcontext {
  __u64 sc_pc;
  __u64 sc_regs[32];
  __u32 sc_flags;
  __u64 sc_extcontext[0] __attribute__((__aligned__(16)));
};

#define CONTEXT_INFO_ALIGN 16
struct sctx_info {
  __u32 magic;
  __u32 size;
  __u64 padding; /* padding to 16 bytes */
};

/* LASX context */
#define LASX_CTX_MAGIC 0x41535801
#define LASX_CTX_ALIGN 32
struct lasx_context {
  __u64 regs[4 * 32];
  __u64 fcc;
  __u32 fcsr;
};

/* LBT context */
#define LBT_CTX_MAGIC 0x42540001
#define LBT_CTX_ALIGN 8
struct lbt_context {
  __u64 regs[4];
  __u32 eflags;
  __u32 ftop;
};

// /usr/include/asm/ucontext.h

struct ucontext {
  unsigned long uc_flags;
  struct ucontext *uc_link;
  stack_t uc_stack;
  sigset_t uc_sigmask;
  /* There's some padding here to allow sigset_t to be expanded in the
   * future.  Though this is unlikely, other architectures put uc_sigmask
   * at the end of this structure and explicitly state it can be
   * expanded, so we didn't want to box ourselves in here. */
  __u8 __unused[1024 / 8 - sizeof(sigset_t)];
  /* We can't put uc_sigmask at the end of this structure because we need
   * to be able to expand sigcontext in the future.  For example, the
   * vector ISA extension will almost certainly add ISA state.  We want
   * to ensure all user-visible ISA state can be saved and restored via a
   * ucontext, so we're putting this at the end in order to allow for
   * infinite extensibility.  Since we know this will be extended and we
   * assume sigset_t won't be extended an extreme amount, we're
   * prioritizing this. */
  struct sigcontext uc_mcontext;
};

// /usr/include/sys/ucontext.h

typedef struct mcontext_t {
  unsigned long long __pc;
  unsigned long long __gregs[32];
  unsigned int __flags;
  unsigned long long __extcontext[0] __attribute__((__aligned__(16)));
} mcontext_t;

/* Userlevel context.  */
typedef struct ucontext_t {
  unsigned long int __uc_flags;
  struct ucontext_t *uc_link;
  stack_t uc_stack;
  sigset_t uc_sigmask;
  mcontext_t uc_mcontext;
} ucontext_t;

// Licenses of the code copied from glibc:
/* Copyright (C) 2022-2023 Free Software Foundation, Inc.

   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library.  If not, see
   <https://www.gnu.org/licenses/>.  */
