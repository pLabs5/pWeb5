#include "stub_cfg.h"

int cfg_get(const char *key, char *out, unsigned long cap) {
  (void)key; (void)out; (void)cap;
  return -1;
}

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

/* The bundled resolver quietly assumes dRPC5's log and monotonic-time
 * helpers; the dispatcher has its own logger, so the timestamp goes through
 * the clock directly and the failure line goes to stdout. */
long long mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void dlogf(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stdout, fmt, args);
  va_end(args);
}
