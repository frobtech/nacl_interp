/*
 * Copyright (c) 2011 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * This program provides a hack for running dynamically-linked NaCl
 * executables directly on a Linux host.  This standalone program
 * must be compiled with -fPIC -shared to make it a special-purpose
 * shared object, which can act as a replacement for the dynamic linker.
 * Then a symlink to this object must be installed in the location
 * that appears in the PT_INTERP of a nexe for the platform in question.
 * That is, the appropriate one of:
 *      /lib/ld-nacl-x86-32.so.1
 *      /lib64/ld-nacl-x86-64.so.1
 *      /lib/ld-nacl-arm.so.1
 *
 * Thereafter, running a nexe will actually run this program, which will do:
 *      exec ${NACL_INTERP_LOADER} PLATFORM NEXE ARGS...
 * That is, NACL_INTERP_LOADER should be set in the environment to an
 * appropriate wrapper script that runs the right sel_ldr with the
 * right -B .../irt_core.nexe switch (and other appropriate switches,
 * usually -a among them).
 *
 * PLATFORM will be x86_64, i[3456]86, etc. as seen in AT_PLATFORM.
 * If you aren't sure what your Linux system produces, try running:
 *      LD_SHOW_AUXV=1 /bin/true | fgrep AT_PLATFORM
 *
 * NEXE is the name of the original executable, and ARGS... are its
 * arguments (the first being its argv[0], i.e. program name).
 *
 * The wrapper script can use the PLATFORM argument to select the
 * appropriate sel_ldr et al to use.
 */

#include <elf.h>
#include <linux/limits.h>
#include <link.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * Get inline functions for system calls.
 */
static int my_errno;
#define SYS_ERRNO my_errno
#include "lss/linux_syscall_support.h"

#define ENVAR "NACL_INTERP_LOADER"

static const char *environ_match(const char *name, const char *envstring) {
  const char *a = name;
  const char *b = envstring;
  while (*a == *b) {
    if (*a == '\0')
      return NULL;
    ++a;
    ++b;
  }
  if (*a == '\0' && *b == '=')
    return b + 1;
  return NULL;
}

static const char *my_getenv(const char *name, const char *const *envp) {
  const char *const *ep;
  for (ep = envp; *ep != NULL; ++ep) {
    const char *match = environ_match(name, *ep);
    if (match != NULL)
      return match;
  }
  return NULL;
}

static size_t my_strlen(const char *s) {
  size_t n = 0;
  while (*s++ != '\0')
    ++n;
  return n;
}

/*
 * We're avoiding libc, so no printf.  The only nontrivial thing we need
 * is rendering numbers, which is, in fact, pretty trivial.
 * bufsz of course must be enough to hold INT_MIN in decimal.
 */
static void iov_int_string(int value, struct kernel_iovec *iov,
                           char *buf, size_t bufsz) {
  char *p = &buf[bufsz];
  int negative = value < 0;
  if (negative)
    value = -value;
  do {
    --p;
    *p = "0123456789"[value % 10];
    value /= 10;
  } while (value != 0);
  if (negative)
    *--p = '-';
  iov->iov_base = p;
  iov->iov_len = &buf[bufsz] - p;
}

#define STRING_IOV(string_constant, cond) \
  { (void *) string_constant, cond ? (sizeof(string_constant) - 1) : 0 }

__attribute__((noreturn)) static void fail(const char *message,
                                           const char *filename,
                                           const char *item1, int value1) {
  char valbuf1[32];
  struct kernel_iovec iov[] = {
    STRING_IOV("nacl_interp: ", 1),
    { (void *) message, my_strlen(message) },
    { (void *) filename, filename == NULL ? 0 : my_strlen(filename) },
    STRING_IOV(": ", item1 != NULL),
    { (void *) item1, item1 == NULL ? 0 : my_strlen(item1) },
    STRING_IOV("=", item1 != NULL),
    { NULL, 0 },                        /* iov[6] */
    { "\n", 1 },
  };
  const int niov = sizeof(iov) / sizeof(iov[0]);

  if (item1 != NULL)
    iov_int_string(value1, &iov[6], valbuf1, sizeof(valbuf1));

  sys_writev(2, iov, niov);
  sys_exit_group(2);
  while (1) *(volatile int *) 0 = 0;  /* Crash.  */
}

/*
 * This declaration tells the compiler that there is a caller even though
 * it can't see it in the C code.  It also specifies the symbol name to use
 * in assembly (not really necessary in practice), ensuring that the name
 * the assembly code below uses will work.  This function has to be static
 * so that the assembler will know it doesn't need to generate a reloc for
 * the call to it.
 */
static void do_start(uintptr_t *stack) asm("do_start")
    __attribute__((noreturn, used));

static void do_start(uintptr_t *stack) {
  /*
   * First find the end of the auxiliary vector.
   */
  int argc = stack[0];
  const char *const *argv = (const char *const *) &stack[1];
  const char *const *envp = &argv[argc + 1];
  const char *const *ep = envp;
  while (*ep != NULL)
    ++ep;
  ElfW(auxv_t) *auxv = (ElfW(auxv_t) *) (ep + 1);
  ElfW(auxv_t) *av = auxv;
  while (av->a_type != AT_NULL)
    ++av;

  const char *execfn = NULL;
  const char *platform = NULL;
  bool secure = true;

  for (av = auxv; av->a_type != AT_NULL; ++av)
    switch (av->a_type) {
      case AT_EXECFN:
        execfn = (const char *) av->a_un.a_val;
        break;
      case AT_PLATFORM:
        platform = (const char *) av->a_un.a_val;
        break;
      case AT_SECURE:
        secure = av->a_un.a_val != 0;
        break;
    }

  if (execfn == NULL) {
    static char buf[PATH_MAX + 1];
    ssize_t n = sys_readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n >= 0) {
      buf[n] = '\0';
      execfn = buf;
    } else {
      execfn = argv[0];
    }
  }

  if (secure)
    fail("refusing secure exec of ", execfn, NULL, 0);

  if (platform == NULL) {
#if defined(__x86_64__)
    platform = "x86_64";
#elif defined(__i386__)
    platform = "i386";
#elif defined(__arm__)
    platform = "arm";
#elif defined(__mips__)
    platform = "mips";
#else
# error "Don't know default platform!"
#endif
  }

  {
    const char *loader = my_getenv(ENVAR, envp);
    const char *new_argv[argc + 4];
    int i;

    if (loader == NULL)
      fail("environment variable " ENVAR
           " must be set to run a NaCl binary directly", NULL, NULL, 0);

    new_argv[0] = loader;
    new_argv[1] = platform;
    new_argv[2] = execfn;
    for (i = 1; i <= argc; ++i)
      new_argv[2 + i] = argv[i];

    sys_execve(loader, (const char *const *) new_argv, envp);

    fail("failed to execute ", loader, "errno", my_errno);
  }
}

/*
 * We have to define the actual entry point code (_start) in assembly for
 * each machine.  The kernel startup protocol is not compatible with the
 * normal C function calling convention.  Here, we call do_start (above)
 * using the normal C convention as per the ABI, with the starting stack
 * pointer as its argument.
 */
#if defined(__i386__)
asm(".pushsection \".text\",\"ax\",@progbits\n"
    ".globl _start\n"
    ".type _start,@function\n"
    "_start:\n"
    "xorl %ebp, %ebp\n"
    "movl %esp, %eax\n"         /* Fetch the incoming stack pointer.  */
    "andl $-16, %esp\n"         /* Align the stack as per ABI.  */
    "pushl %eax\n"              /* Argument: stack block.  */
    "call do_start\n"
    "hlt\n"			/* Never reached.  */
    ".popsection"
    );
#elif defined(__x86_64__)
asm(".pushsection \".text\",\"ax\",@progbits\n"
    ".globl _start\n"
    ".type _start,@function\n"
    "_start:\n"
    "xorq %rbp, %rbp\n"
    "movq %rsp, %rdi\n"         /* Argument: stack block.  */
    "andq $-16, %rsp\n"         /* Align the stack as per ABI.  */
    "call do_start\n"
    "hlt\n"			/* Never reached.  */
    ".popsection"
    );
#elif defined(__arm__)
asm(".pushsection \".text\",\"ax\",%progbits\n"
    ".globl _start\n"
    ".type _start,#function\n"
    "_start:\n"
#if defined(__thumb2__)
    ".thumb\n"
    ".syntax unified\n"
#endif
    "mov fp, #0\n"
    "mov lr, #0\n"
    "mov r0, sp\n"              /* Argument: stack block.  */
    "b   do_start\n"
    ".popsection"
    );
#elif defined(__mips__)
asm(".pushsection \".text\",\"ax\",%progbits\n"
    ".globl _start\n"
    ".type _start,@function\n"
    "_start:\n"
    ".set noreorder\n"
    "addiu $fp, $zero, 0\n"
    "addiu $ra, $zero, 0\n"
    "addiu $a0, $sp,   0\n"
    "addiu $sp, $sp, -16\n"
    "jal   do_start\n"
    "nop\n"
    ".popsection"
    );
#else
# error "Need _start code for this architecture!"
#endif

#if defined(__arm__)
/*
 * We may bring in __aeabi_* functions from libgcc that in turn
 * want to call raise.
 */
int raise(int sig) {
  return sys_kill(sys_getpid(), sig);
}
#endif
