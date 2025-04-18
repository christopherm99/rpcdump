// Copyright (c) 2025 Christopher Milan.
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <linux/limits.h>
#include <errno.h>
#include <task.h>

#include "uthash.h"

#define MAX_FD 1023
#define TRAP_CAUSE(s) (((s) >> 16) & 0xffff)

extern void Decode(void *p, int n);

struct tracee {
  int            pid;
  int            mem;
  Channel       *chan;
  bool           entering;
  UT_hash_handle hh;
  bool           fds[MAX_FD + 1];
};

struct tracee *tracee_map = NULL;

struct tracee *add_tracee(pid_t pid) {
  int mem;
  char filename[PATH_MAX];
  struct tracee *e = calloc(1, sizeof(struct tracee));

  sprintf(filename, "/proc/%d/mem", pid);

  e->pid = pid;
  e->mem = mem;
  e->chan = chancreate(sizeof(int), 0);
  e->entering = true;
  HASH_ADD_INT(tracee_map, pid, e);
  return e;
}

Channel *lookup_chan(pid_t pid) {
  struct tracee *e;
  HASH_FIND_INT(tracee_map, &pid, e);
  return e ? e->chan : NULL;
}

void del_tracee(struct tracee *e) {
  close(e->mem);
  chanfree(e->chan);
  HASH_DEL(tracee_map, e);
  free(e);
}

void broker(void) {                                                                                                                                                                                                                                                                                   taskname("broker");
  tasksystem();

  while (1) {
    int status;
    pid_t pid;
    Channel *c;

    taskstate("waitpid");

    if ((pid = waitpid(-1, &status, __WALL)) == -1) {
      if (errno == EINTR) continue;
      if (errno == ECHILD) taskexit(0);
      perror("waitpid");
      taskexitall(1);
    }

    c = lookup_chan(pid);
    if (c) {
      taskstate("sending to %d", pid);
      chansend(c, &status);
      taskstate("yielding");
      taskyield();
    }
  }
}

void shutdown(struct tracee *t, int code, char *msg) {
  if (code) fprintf(stderr, "[%d] +++ %s (%s) +++\n", t->pid, msg, strerror(code));
  del_tracee(t);
  taskexit(code);
}

void trace(struct tracee *t) {
  taskname("trace (%d)", t->pid);

  while (1) {
    int ws;
    struct user_regs_struct regs;

    if (ptrace(PTRACE_SYSCALL, t->pid, NULL, NULL) == -1 && errno != ESRCH) shutdown(t, errno, "ptrace syscall");

    taskstate("waiting for child");

    chanrecv(t->chan, &ws);

    taskstate("processing syscall");

    if (WIFEXITED(ws)) shutdown(t, WEXITSTATUS(ws), "exited");

    if (WIFSTOPPED(ws) && WSTOPSIG(ws) == SIGTRAP && TRAP_CAUSE(ws) != 0) {
      int msg;
      struct tracee *child;

      if (ptrace(PTRACE_GETEVENTMSG, t->pid, NULL, &msg) == -1) shutdown(t, errno, "ptrace geteventmsg");
      taskcreate((void (*)(void *))trace, add_tracee(msg), 8192);
      continue;
    }

    if (!WIFSTOPPED(ws) || WSTOPSIG(ws) != (SIGTRAP | 0x80)) continue;

    if (ptrace(PTRACE_GETREGS, t->pid, NULL, &regs) == -1) shutdown(t, errno, "ptrace getregs");

    if (t->entering) {
      switch (regs.orig_rax) {
      case SYS_write:
        if (regs.rdi > MAX_FD) shutdown(t, 0, "too many file descriptors");
        if (t->fds[regs.rdi]) {
          void *buf = malloc(regs.rdi);
          fprintf(stderr, "[%d] WRITE(%llu) -- %d: ", t->pid, regs.rdi, (int)regs.rdx);
          pread(t->mem, buf, regs.rdx, (long)regs.rsi);
          Decode(buf, (int)regs.rdx);
          fprintf(stderr, "\n");
        }
        break;
      }
    } else {
      switch (regs.orig_rax) {
      case SYS_socket:
        if (regs.rax >= 0) t->fds[regs.rax] = true;
        break;
      }
    }

    t->entering = !t->entering;
  }
}


void taskmain(int argc, char **argv) {
  pid_t root;

  if (argc < 2) {
    fprintf(stderr, "usage: rpcdump PROG [ARGS]\n");
    taskexit(1);
  }

  if ((root = fork()) == 0) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execvp(argv[1], &argv[1]);
  }

  if (wait(NULL) == -1) {
    perror("wait");
    taskexit(1);
  }

  if (ptrace(PTRACE_SETOPTIONS, root, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC |
      PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE) == -1) {
    perror("ptrace");
    taskexit(1);
  }


  taskcreate((void (*)(void *))trace, add_tracee(root), 8192);
  taskcreate((void (*)(void *))broker, NULL, 8192);
}

