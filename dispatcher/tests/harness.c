/* Host test harness for the dispatcher's decision logic.
 *
 * Includes main.c directly so the parser, the local: confinement check and
 * the kstuff selection are tested as written rather than reimplemented. The
 * Sce calls are stubbed: firmware comes from $TEST_FW and "HTTPS" is served
 * out of $TEST_HTTP_ROOT, which is enough to exercise every path that does
 * not touch a real socket.
 *
 * Build/run through tests/run.sh - LOCAL_ROOT and CLOUD_BASE are overridden
 * there to point inside the test's temp dir.
 */

#define main dispatcher_main
#include "../main.c"
#undef main

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char stub_url[1024];
static FILE *stub_fp;

int sceKernelGetProsperoSystemSwVersion(void *buf) {
  uint32_t size, fw = 0;
  const char *env = getenv("TEST_FW");
  if (!env) return -1;
  fw = (uint32_t)strtoul(env, NULL, 0);
  size = 0x18;
  memcpy(buf, &size, sizeof(size));
  memcpy((char *)buf + 0x14, &fw, sizeof(fw));
  return 0;
}

int sceNetInit(void) { return 0; }
int sceNetPoolCreate(const char *n, int a, int b) { return 1; }
int sceNetPoolDestroy(int p) { return 0; }
int sceSslInit(size_t s) { return 1; }
int sceSslTerm(int c) { return 0; }
int sceHttp2Init(int a, int b, size_t c, int d) { return 1; }
int sceHttp2Term(int c) { return 0; }
int sceHttp2CreateTemplate(int c, const char *u, int a, int b) { return 1; }
int sceHttp2DeleteTemplate(int t) { return 0; }

int sceHttp2CreateRequestWithURL(int t, const char *m, const char *url,
                                  uint64_t v) {
  snprintf(stub_url, sizeof(stub_url), "%s", url);
  return 1;
}

int sceHttp2DeleteRequest(int r) {
  if (stub_fp) fclose(stub_fp);
  stub_fp = NULL;
  return 0;
}

int sceHttp2SendRequest(int r, const void *d, size_t n) {
  const char *slash = strstr(stub_url, "://");
  char path[1024];
  const char *root = getenv("TEST_HTTP_ROOT");

  slash = slash ? slash + 3 : stub_url;
  slash = strchr(slash, '/');
  snprintf(path, sizeof(path), "%s%s", root ? root : "", slash ? slash : "");

  if (!(stub_fp = fopen(path, "rb"))) return -1;
  return 0;
}

int sceHttp2GetStatusCode(int r, int *out) {
  *out = stub_fp ? 200 : 404;
  return 0;
}

int sceHttp2ReadData(int r, void *buf, size_t cap) {
  size_t n;
  if (!stub_fp || !buf || !cap) return 0;
  n = fread(buf, 1, cap, stub_fp);
  return (int)n;
}

int main(void) { return dispatcher_main(); }
