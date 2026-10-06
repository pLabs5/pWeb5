/* pWeb5 payload dispatcher.
 *
 * Loaded by elfldr on :9021 after the JS chain has brought the listener up.
 * The page's job ends the moment this lands; everything after that - reading
 * the console-local manifest, falling back to the cloud one, and streaming
 * each payload into elfldr - happens here, so a closed or backgrounded
 * WebView cannot strand the rest of the chain.
 *
 * Build:  bash build.sh     (see Makefile)
 * Test:   DISPATCHER_DRYRUN=1 on the console logs the plan without sending.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

/* libSceNet / libSceSsl / libSceHttp2. The SDK ships no headers for these,
 * so the prototypes are declared here the way the SDK's own samples do. */
int sceNetInit(void);
int sceNetPoolCreate(const char *, int, int);
int sceNetPoolDestroy(int);
int sceSslInit(size_t);
int sceSslTerm(int);
int sceHttp2Init(int, int, size_t, int);
int sceHttp2Term(int);
int sceHttp2CreateTemplate(int, const char *, int, int);
int sceHttp2DeleteTemplate(int);
int sceHttp2CreateRequestWithURL(int, const char *, const char *, uint64_t);
int sceHttp2DeleteRequest(int);
int sceHttp2SendRequest(int, const void *, size_t);
int sceHttp2GetStatusCode(int, int *);
int sceHttp2ReadData(int, void *, size_t);

/* PS5 kernel firmware-version probe. Argument is a 0x18-byte struct:
 * uint32_t size at offset 0, BCD-packed version uint32 at offset 0x14
 * (e.g. 0x10010000 = 10.01, 0x12000000 = 12.00). */
int sceKernelGetProsperoSystemSwVersion(void *buf);

#ifndef CLOUD_BASE
#define CLOUD_BASE "https://pweb5.pages.dev"
#endif
#ifndef LOCAL_ROOT
#define LOCAL_ROOT "/data/autoldr"
#endif

#define LOCAL_MANIFEST LOCAL_ROOT "/manifest.txt"
#define LOG_PATH LOCAL_ROOT "/dispatcher.log"
#define ELFDR_PORT 9021
#define MAX_ENTRIES 64
#define MAX_NAME 128
#define MAX_TARGET 512
#define MAX_MANIFEST 0x10000
#define HTTP_POOL 512 * 1024
#define HTTP_BUFSZ 64 * 1024
#define GAP_SECONDS 5
#define HTTP_ATTEMPTS 3
/* elfldr accepts one connection at a time and is still busy unmapping the
 * dispatcher itself when main() starts, so the first connect can lose the
 * race. Waiting here is not the 5s guess the page used; it is bounded and
 * only pays out when the listener really is absent. */
#define ELFDR_WAIT_SECONDS 30

/* Full kstuff is supported up to and including 10.01; 0x10010000 == 10.01. */
#define KSTUFF_FULL_MAX 0x10010000u

struct entry {
  char name[MAX_NAME];
  char target[MAX_TARGET];
  int is_local;
  int is_url;
};

static struct entry g_entries[MAX_ENTRIES];
static int g_count;
static int g_dryrun;
static int g_planonly;

static int g_net_mem = -1;
static int g_ssl_ctx = -1;
static int g_http_ctx = -1;
static int g_tmpl = -1;

/* ------------------------------------------------------------------ */

static void
logmsg(const char *fmt, ...)
{
  va_list args;
  char line[1024];
  int n;
  FILE *fp;

  va_start(args, fmt);
  n = vsnprintf(line, sizeof(line), fmt, args);
  va_end(args);
  if (n < 0) return;
  printf("%s\n", line);
  fflush(stdout);

  if ((fp = fopen(LOG_PATH, "a"))) {
    fprintf(fp, "%s\n", line);
    fclose(fp);
  }
}

/* The version is BCD-packed, not binary: 12.00 is 0x12000000, so reading the
 * major byte as a plain number says 18. Ordering still works on the raw value
 * because BCD digits compare in the same order as decimal ones, which is why
 * the kstuff cutoff can stay a plain <= against 0x10010000. */
static int
bcd_digit(uint32_t byte)
{
  return (int)((byte >> 4) * 10 + (byte & 0x0f));
}

static int
is_bcd(uint32_t byte)
{
  return ((byte >> 4) <= 9) && ((byte & 0x0f) <= 9);
}

static uint32_t
firmware_version(void)
{
  uint8_t buf[0x18] = {0};
  uint32_t fw;

  /* The size field goes in first; the call writes nothing without it. */
  *(uint32_t *)buf = sizeof(buf);
  if (sceKernelGetProsperoSystemSwVersion(buf) != 0) return 0;
  fw = *(uint32_t *)&buf[0x14];
  return fw;
}

/* ------------------------------------------------------------------ */

static void
http_init(void)
{
  if (g_http_ctx != -1) return;

  if (sceNetInit()) {
    logmsg("http: sceNetInit failed");
    return;
  }
  if ((g_net_mem = sceNetPoolCreate("dispatcher", HTTP_POOL, 0)) < 0) {
    logmsg("http: sceNetPoolCreate failed (%d)", g_net_mem);
    g_net_mem = -1;
    return;
  }
  if ((g_ssl_ctx = sceSslInit(HTTP_POOL)) < 0) {
    logmsg("http: sceSslInit failed (%d)", g_ssl_ctx);
    g_ssl_ctx = -1;
    sceNetPoolDestroy(g_net_mem);
    g_net_mem = -1;
    return;
  }
  if ((g_http_ctx = sceHttp2Init(g_net_mem, g_ssl_ctx, HTTP_POOL, 1)) < 0) {
    logmsg("http: sceHttp2Init failed (%d)", g_http_ctx);
    g_http_ctx = -1;
    sceSslTerm(g_ssl_ctx);
    g_ssl_ctx = -1;
    sceNetPoolDestroy(g_net_mem);
    g_net_mem = -1;
    return;
  }
  g_tmpl = sceHttp2CreateTemplate(g_http_ctx, "pweb5-dispatcher/1.0", 3, 1);
  if (g_tmpl < 0) logmsg("http: sceHttp2CreateTemplate failed (%d)", g_tmpl);
}

static void
http_fini(void)
{
  if (g_tmpl >= 0) sceHttp2DeleteTemplate(g_tmpl);
  if (g_http_ctx >= 0) sceHttp2Term(g_http_ctx);
  if (g_ssl_ctx >= 0) sceSslTerm(g_ssl_ctx);
  if (g_net_mem >= 0) sceNetPoolDestroy(g_net_mem);
  g_tmpl = g_http_ctx = g_ssl_ctx = g_net_mem = -1;
}

/* Fetch a URL into a malloc'd buffer. Caller frees. */
static uint8_t *
http_get_once(const char *url, size_t *out_len)
{
  uint8_t *buf = NULL;
  size_t cap = 0, len = 0;
  int req, status = 0, got;

  *out_len = 0;
  http_init();
  if (g_tmpl < 0) return NULL;

  if ((req = sceHttp2CreateRequestWithURL(g_tmpl, "GET", url, 0)) < 0) {
    logmsg("http: cannot create request for %s (%d)", url, req);
    return NULL;
  }
  if (sceHttp2SendRequest(req, NULL, 0) || sceHttp2GetStatusCode(req, &status)) {
    logmsg("http: request failed for %s", url);
    sceHttp2DeleteRequest(req);
    return NULL;
  }
  if (status != 200) {
    logmsg("http: %s returned status %d", url, status);
    sceHttp2DeleteRequest(req);
    return NULL;
  }

  /* ReadData needs a real buffer and reports 0 at end of body. Grow
   * geometrically so a multi-megabyte payload does not realloc per chunk. */
  for (;;) {
    size_t want = len + HTTP_BUFSZ + 1;
    if (want > cap) {
      size_t next = cap ? cap * 2 : HTTP_BUFSZ * 2;
      uint8_t *tmp;
      while (next < want) next *= 2;
      if (!(tmp = realloc(buf, next))) {
        free(buf);
        sceHttp2DeleteRequest(req);
        return NULL;
      }
      buf = tmp;
      cap = next;
    }
    got = sceHttp2ReadData(req, buf + len, cap - len - 1);
    if (got <= 0) break;
    len += (size_t)got;
  }
  sceHttp2DeleteRequest(req);

  if (!buf) return NULL;
  buf[len] = '\0';
  *out_len = len;
  return buf;
}

static uint8_t *
http_get(const char *url, size_t *out_len)
{
  uint8_t *data = NULL;
  int attempt;

  *out_len = 0;
  for (attempt = 1; attempt <= HTTP_ATTEMPTS; attempt++) {
    if ((data = http_get_once(url, out_len))) return data;
    if (attempt < HTTP_ATTEMPTS) {
      logmsg("http: attempt %d/%d failed for %s, retrying", attempt, HTTP_ATTEMPTS,
           url);
      sleep(2);
    }
  }
  return NULL;
}

static uint8_t *
read_file(const char *path, size_t *out_len, size_t cap_max)
{
  struct stat st;
  uint8_t *buf;
  int fd;
  ssize_t n;

  *out_len = 0;
  if ((fd = open(path, O_RDONLY)) < 0) return NULL;
  if (fstat(fd, &st) || st.st_size <= 0 || (size_t)st.st_size > cap_max) {
    close(fd);
    return NULL;
  }
  if (!(buf = malloc((size_t)st.st_size + 1))) {
    close(fd);
    return NULL;
  }
  n = read(fd, buf, (size_t)st.st_size);
  close(fd);
  if (n != st.st_size) {
    free(buf);
    return NULL;
  }
  buf[n] = '\0';
  *out_len = (size_t)n;
  return buf;
}

/* ------------------------------------------------------------------ */

/* A local: target must stay under LOCAL_ROOT and must not traverse out of it.
 * The prefix alone is not confinement - the kernel resolves ".." on open - so
 * the traversal check has to happen here too. */
static int
local_target_ok(const char *path)
{
  const char *p;
  size_t rootlen = strlen(LOCAL_ROOT);

  if (strncmp(path, LOCAL_ROOT "/", rootlen + 1) != 0) {
    logmsg("manifest: local target must be under %s/, got %s", LOCAL_ROOT, path);
    return 0;
  }
  for (p = path; p && *p;) {
    const char *slash = strchr(p, '/');
    size_t len = slash ? (size_t)(slash - p) : strlen(p);
    if (len == 2 && p[0] == '.' && p[1] == '.') {
      logmsg("manifest: local target must not contain .., got %s", path);
      return 0;
    }
    if (!slash) break;
    p = slash + 1;
  }
  return 1;
}

static void
add_entry(const char *name, const char *target)
{
  struct entry *e;

  if (g_count >= MAX_ENTRIES) {
    logmsg("manifest: too many entries, ignoring %s", name);
    return;
  }
  e = &g_entries[g_count];
  snprintf(e->name, sizeof(e->name), "%s", name);
  e->is_local = e->is_url = 0;

  if (!strncasecmp(target, "local:", 6)) {
    const char *path = target + 6;
    if (!local_target_ok(path)) return;
    snprintf(e->target, sizeof(e->target), "%s", path);
    e->is_local = 1;
  } else if (!strncasecmp(target, "http://", 7) ||
             !strncasecmp(target, "https://", 8) ||
             !strncmp(target, "//", 2)) {
    if (!strncmp(target, "//", 2)) {
      /* Protocol-relative: the page scheme was https, so say so. */
      snprintf(e->target, sizeof(e->target), "https:%s", target);
    } else {
      snprintf(e->target, sizeof(e->target), "%s", target);
    }
    e->is_url = 1;
  } else if (strchr(target, ':')) {
    logmsg("manifest: %s must be an http, https or local: target, got %s", name,
         target);
    return;
  } else {
    /* A bare name resolves against the site's payloads/ directory. The
     * manifest writes entries both ways - "etahen.elf" and
     * "etahen.elf=payloads/etaHEN.elf" - so an explicit payloads/ prefix has
     * to collapse rather than stack, or every entry comes out as
     * payloads/payloads/... and 404s. */
    const char *file = target;
    if (!strncmp(file, "payloads/", 9)) file += 9;
    snprintf(e->target, sizeof(e->target), "%s/payloads/%s", CLOUD_BASE, file);
    e->is_url = 1;
  }
  g_count++;
}

static void
parse_manifest(char *text)
{
  char *line = text;

  while (line && *line) {
    char *eol = strpbrk(line, "\r\n");
    char *eq;
    char *hash;

    if (eol) *eol = '\0';

    /* Strip a trailing comment too: a target left with " # ..." appended
     * would be opened as a literal path and simply fail. */
    if ((hash = strchr(line, '#'))) *hash = '\0';

    while (*line == ' ' || *line == '\t') line++;
    {
      size_t l = strlen(line);
      while (l && (line[l - 1] == ' ' || line[l - 1] == '\t')) line[--l] = '\0';
    }

    if (*line) {
      if ((eq = strchr(line, '='))) {
        *eq = '\0';
        add_entry(line, eq + 1);
      } else {
        add_entry(line, line);
      }
    }
    line = eol ? eol + 1 : NULL;
  }
}

/* kstuff has to land first because it is what makes the rest work. A kstuff
 * line in the manifest is the owner's choice of build, so it wins outright;
 * with none named, firmware decides. */
static void
force_kstuff_first(uint32_t fw)
{
  struct entry kept[MAX_ENTRIES];
  int kept_count = 0;
  struct entry ks;
  int i, have_named = 0;

  memset(&ks, 0, sizeof(ks));
  for (i = 0; i < g_count; i++) {
    if (strcasestr(g_entries[i].name, "kstuff")) {
      ks = g_entries[i];
      have_named = 1;
    } else {
      kept[kept_count++] = g_entries[i];
    }
  }

  if (!have_named) {
    const char *file;
    memset(&ks, 0, sizeof(ks));
    /* Unknown firmware picks the modern build, which is the safer guess. */
    if (fw != 0 && fw <= KSTUFF_FULL_MAX) {
      snprintf(ks.name, sizeof(ks.name), "kstuff.elf");
      file = "kstuff.elf";
    } else {
      snprintf(ks.name, sizeof(ks.name), "kstuff-lite.elf");
      file = "kstuff-lite-1.11B.elf";
    }
    snprintf(ks.target, sizeof(ks.target), "%s/payloads/%s", CLOUD_BASE, file);
    ks.is_url = 1;
  }

  memcpy(&g_entries[1], kept, (size_t)kept_count * sizeof(kept[0]));
  g_entries[0] = ks;
  g_count = kept_count + 1;
}

/* ------------------------------------------------------------------ */

/* Block until elfldr is accepting again, or give up. Returns the fd. */
static int
elfdr_connect(void)
{
  int waited = 0;

  for (;;) {
    struct sockaddr_in sa;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
      logmsg("elfldr: socket: %s", strerror(errno));
      return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(ELFDR_PORT);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) return fd;
    close(fd);

    if (waited >= ELFDR_WAIT_SECONDS) {
      logmsg("elfldr: nothing on :%d after %ds", ELFDR_PORT, waited);
      return -1;
    }
    if (waited == 0)
      logmsg("elfldr: not accepting yet, waiting for the previous payload");
    sleep(1);
    waited++;
  }
}

static int
send_to_elfldr(const char *name, const uint8_t *data, size_t len)
{
  size_t off = 0;
  int fd, i;

  if ((fd = elfdr_connect()) < 0) {
    logmsg("%s: cannot reach elfldr on :%d", name, ELFDR_PORT);
    return -1;
  }

  while (off < len) {
    ssize_t w = write(fd, data + off, len - off);
    if (w <= 0) {
      logmsg("%s: write failed at %zu/%zu: %s", name, off, len, strerror(errno));
      close(fd);
      return -1;
    }
    off += (size_t)w;
  }

  /* Read back whatever the console says about it. This is the only real
   * signal available about whether a payload took; the old fixed sleep in
   * the page was a guess. */
  for (i = 0; i < 8; i++) {
    struct pollfd pfd;
    char buf[4096];
    ssize_t n;

    pfd.fd = fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 1000) <= 0) break;
    if (!(n = recv(fd, buf, sizeof(buf) - 1, 0))) break;
    if (n < 0) break;
    buf[n] = '\0';
    {
      char *line = buf;
      while (line && *line) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        if (*line) logmsg("%s: %s", name, line);
        line = nl ? nl + 1 : NULL;
      }
    }
  }

  close(fd);
  return 0;
}

/* ------------------------------------------------------------------ */

int
main(void)
{
  uint32_t fw;
  char *local = NULL;
  size_t len;
  int i;

  /* DISPATCHER_DRYRUN fetches and validates the whole plan but sends nothing.
   * DISPATCHER_PLAN_ONLY stops earlier still, before any fetch, for when there
   * is no network to fetch from and only the resolved plan matters. */
  g_dryrun = getenv("DISPATCHER_DRYRUN") != NULL;
  g_planonly = getenv("DISPATCHER_PLAN_ONLY") != NULL;

  if ((fw = firmware_version()) != 0) {
    uint32_t major = (fw >> 24) & 0xff, minor = (fw >> 16) & 0xff;
    if (is_bcd(major) && is_bcd(minor))
      logmsg("dispatcher: firmware %u.%02u (0x%08x)", (unsigned)bcd_digit(major),
             (unsigned)bcd_digit(minor), fw);
    else
      /* Not BCD, so it is not the layout documented for this call. Say the raw
       * value rather than a confident wrong version number. */
      logmsg("dispatcher: firmware 0x%08x (not BCD, unrecognised)", fw);
  } else {
    logmsg("dispatcher: firmware version unavailable, assuming modern");
  }

  if ((local = (char *)read_file(LOCAL_MANIFEST, &len, MAX_MANIFEST))) {
    logmsg("dispatcher: using console-local manifest %s (%zu bytes)", LOCAL_MANIFEST,
         len);
    parse_manifest(local);
    free(local);
  } else {
    char url[512];
    char *cloud;
    snprintf(url, sizeof(url), "%s/manifest.txt", CLOUD_BASE);
    logmsg("dispatcher: no local manifest, fetching %s", url);
    if (!(cloud = (char *)http_get(url, &len))) {
      logmsg("dispatcher: cloud manifest unavailable");
      return 1;
    }
    logmsg("dispatcher: using cloud manifest (%zu bytes)", len);
    parse_manifest(cloud);
    free(cloud);
  }

  if (!g_count) {
    logmsg("dispatcher: manifest produced no entries");
    return 1;
  }

  force_kstuff_first(fw);

  logmsg("dispatcher: %d payload(s), %s", g_count,
       g_dryrun ? "DRY RUN - nothing sent" : "dispatching");

  for (i = 0; i < g_count; i++) {
    struct entry *e = &g_entries[i];
    uint8_t *data = NULL;
    size_t size = 0;
    int sent;

    logmsg("[%d/%d] %s <- %s%s", i + 1, g_count, e->name, e->target,
         e->is_local ? " (console-local)" : "");

    if (g_planonly) continue;

    if (e->is_local) {
      data = read_file(e->target, &size, 0x4000000);
      if (!data) {
        logmsg("%s: cannot read %s", e->name, e->target);
        break;
      }
    } else {
      data = http_get(e->target, &size);
      if (!data) {
        logmsg("%s: cannot fetch %s", e->name, e->target);
        break;
      }
    }

    if (size < 0x1000) {
      logmsg("%s: only %zu bytes, too small to be an ELF", e->name, size);
      free(data);
      break;
    }
    if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
      logmsg("%s: %zu bytes but not an ELF (a CDN error page?)", e->name, size);
      free(data);
      break;
    }

    /* A dry run still fetches and checks every payload, because that is the
     * half worth rehearsing: it proves each entry resolves to something real
     * without putting anything on the console. */
    if (g_dryrun) {
      logmsg("%s: %zu bytes, would send to elfldr :%d", e->name, size,
             ELFDR_PORT);
      free(data);
      continue;
    }

    logmsg("%s: sending %zu bytes to elfldr :%d", e->name, size, ELFDR_PORT);
    sent = send_to_elfldr(e->name, data, size);
    free(data);

    if (sent) {
      /* Later payloads depend on earlier ones - etaHEN's FTP server and
       * shadowmountplus' remount in particular - so a hole in the chain is
       * worse than stopping and saying so. */
      logmsg("%s: dispatch failed, stopping the chain here", e->name);
      http_fini();
      return 1;
    }
    logmsg("%s: sent", e->name);

    /* Gap between payloads. etaHEN starts its FTP server the moment it lands
     * and shadowmountplus remounts /system_ex; sending them close together
     * panics the console. */
    if (i < g_count - 1) sleep(GAP_SECONDS);
  }

  http_fini();
  logmsg("dispatcher: done");
  return 0;
}
