/* build - assemble the deployable site into dist/.
 *
 * Replaces tools/build.sh. Compile with cc or `make build`; the binary lives
 * at tools/build/build and finds the repo root from its own path, so it runs
 * from anywhere:
 *
 *     tools/build/build
 *
 * Only the paths below are served. Building a clean directory keeps .git,
 * tools/ and the repo metadata off a public URL, and makes it obvious that
 * everything under payloads/ is published.
 */
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SHALLOW_FILES "index.html", "style.css", "app.js", "manifest.txt", "_headers", "LICENSE"
#define TREE_DIRS "src", "offsets", "payloads", "fonts"
#define READ_CAP 0x1000000
/* The opening tag only; the empty span's own </span> follows it in the file. */
#define BVER_OPEN "<span class=\"bver\" id=\"bver\">"

static void die(const char *fmt, ...) __attribute__((noreturn));

static void die(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fputs("build: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
  exit(1);
}

static void warn(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fputs("build: warning: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
}

static int copy_file(const char *src, const char *dst, unsigned mode) {
  char buf[65536];
  struct stat st;
  int si, di;

  if ((si = open(src, O_RDONLY)) < 0) return -1;
  if (fstat(si, &st) || !S_ISREG(st.st_mode)) {
    close(si);
    errno = EINVAL;
    return -1;
  }
  if ((di = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode ? mode : (st.st_mode & 07777))) < 0) {
    close(si);
    return -1;
  }
  for (;;) {
    ssize_t n = read(si, buf, sizeof buf);
    size_t off = 0;

    if (n == 0) break;
    if (n < 0) {
      if (errno == EINTR) continue;
      close(si);
      close(di);
      return -1;
    }
    while (off < (size_t)n) {
      ssize_t w = write(di, buf + off, (size_t)n - off);
      if (w < 0) {
        if (errno == EINTR) continue;
        close(si);
        close(di);
        return -1;
      }
      off += (size_t)w;
    }
  }
  if (mode) chmod(dst, mode & 07777);
  if (close(si) || close(di)) return -1;
  return 0;
}

static int copy_tree(const char *src, const char *dst) {
  DIR *d;
  struct dirent *de;

  if (mkdir(dst, 0755) && errno != EEXIST) return -1;
  if ((d = opendir(src)) == NULL) return -1;

  while ((de = readdir(d)) != NULL) {
    struct stat st;
    char sp[PATH_MAX], dp[PATH_MAX];

    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
    snprintf(sp, sizeof sp, "%s/%s", src, de->d_name);
    snprintf(dp, sizeof dp, "%s/%s", dst, de->d_name);

    if (lstat(sp, &st) != 0) continue;
    if (S_ISDIR(st.st_mode)) {
      if (copy_tree(sp, dp)) {
        closedir(d);
        return -1;
      }
    } else if (S_ISREG(st.st_mode)) {
      if (copy_file(sp, dp, 0)) {
        closedir(d);
        return -1;
      }
    } else {
      warn("skipping non-regular file %s", sp);
    }
  }
  closedir(d);
  return 0;
}

static int rm_rf(const char *path) {
  struct stat st;
  DIR *d;
  struct dirent *de;

  if (lstat(path, &st) != 0) return errno == ENOENT ? 0 : -1;
  if (!S_ISDIR(st.st_mode)) return unlink(path) ? -1 : 0;

  if ((d = opendir(path)) == NULL) return -1;
  while ((de = readdir(d)) != NULL) {
    char p[PATH_MAX];
    struct stat cs;

    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
    snprintf(p, sizeof p, "%s/%s", path, de->d_name);
    if (lstat(p, &cs) != 0) continue;
    if (S_ISDIR(cs.st_mode)) {
      if (rm_rf(p)) {
        closedir(d);
        return -1;
      }
    } else if (unlink(p)) {
      closedir(d);
      return -1;
    }
  }
  closedir(d);
  return rmdir(path) ? -1 : 0;
}

/* Copy a file at a fixed mode, or die. */
static void install_file(const char *src, const char *dst, unsigned mode) {
  if (copy_file(src, dst, mode))
    die("cannot install %s to %s: %s", src, dst, strerror(errno));
}

static void repo_root(char *own) {
  /* The binary's own path is tools/build/build, so root is two hops up. */
  if (realpath("/proc/self/exe", own)) {
    char *slash = strrchr(own, '/');
    if (slash) *slash = '\0'; /* tools/build */
    slash = strrchr(own, '/');
    if (slash) *slash = '\0'; /* tools */
    slash = strrchr(own, '/');
    if (slash) *slash = '\0'; /* repo root */
    return;
  }
  die("cannot resolve my own path");
}

static char *read_whole(const char *path, size_t *len) {
  struct stat st;
  char *buf;
  size_t n;
  FILE *f;

  if (stat(path, &st) || st.st_size <= 0 || (size_t)st.st_size > READ_CAP) return NULL;
  if (!(buf = malloc((size_t)st.st_size + 1))) return NULL;
  if (!(f = fopen(path, "rb"))) {
    free(buf);
    return NULL;
  }
  n = fread(buf, 1, (size_t)st.st_size, f);
  fclose(f);
  buf[n] = '\0';
  *len = n;
  return buf;
}

static const char *git_short_sha(void) {
  static char sha[64] = "";
  FILE *p;
  size_t l;

  if (sha[0]) return sha;
  if ((p = popen("git rev-parse --short HEAD 2>/dev/null", "r"))) {
    if (fgets(sha, sizeof sha, p)) {
      l = strcspn(sha, "\r\n");
      sha[l] = '\0';
    } else {
      strncpy(sha, "dev", sizeof sha - 1);
    }
    pclose(p);
  }
  if (!sha[0]) strncpy(sha, "dev", sizeof sha - 1);
  return sha;
}

static const char *human(unsigned long long bytes) {
  static char out[32];
  const char *units[] = {"B", "K", "M", "G", "T"};
  double v = (double)bytes;
  int u = 0;

  while (v >= 1024.0 && u < 4) {
    v /= 1024.0;
    u++;
  }
  if (u == 0) snprintf(out, sizeof out, "%lluB", bytes);
  else snprintf(out, sizeof out, "%.1f%s", v, units[u]);
  return out;
}

static void list_tree(const char *dir, const char *rel, unsigned long long *total) {
  DIR *d;
  struct dirent *de;
  char rp[PATH_MAX];

  if ((d = opendir(dir)) == NULL) return;
  while ((de = readdir(d)) != NULL) {
    struct stat st;
    char p[PATH_MAX];

    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
    snprintf(p, sizeof p, "%s/%s", dir, de->d_name);
    if (lstat(p, &st) != 0) continue;
    if (S_ISDIR(st.st_mode)) {
      snprintf(rp, sizeof rp, "%s/%s", rel, de->d_name);
      list_tree(p, rp, total);
    } else if (S_ISREG(st.st_mode)) {
      printf("  %s/%s\n", rel, de->d_name);
      *total += (unsigned long long)st.st_size;
    }
  }
  closedir(d);
}

int main(void) {
  char root[PATH_MAX];
  const char *files[] = {SHALLOW_FILES, NULL};
  const char *dirs[] = {TREE_DIRS, NULL};
  const char *sdk;
  char *idx = NULL;
  size_t idxlen = 0;
  unsigned long long total = 0;
  int i;

  repo_root(root);
  if (chdir(root) != 0) die("cannot cd to repo root %s", root);
  if (rm_rf("dist")) die("cannot clear old dist/");
  if (mkdir("dist", 0755)) die("cannot create dist/: %s", strerror(errno));

  /* The dispatcher is the only payload this site builds, and the page has to
   * be able to fetch it, so it lands in payloads/ before the copy below.
   * Building it here rather than by hand keeps payloads/dispatcher.elf from
   * going stale against dispatcher/main.c. Without an SDK the site still
   * builds - the elf is just left as whatever was last built. */
  sdk = getenv("PS5_PAYLOAD_SDK");
  if (sdk && sdk[0]) {
    puts("building dispatcher.elf");
    if (system("make -C dispatcher") != 0) die("make -C dispatcher failed");
    install_file("dispatcher/dispatcher.elf", "payloads/dispatcher.elf", 0644);
  } else if (access("payloads/dispatcher.elf", F_OK) != 0) {
    warn("PS5_PAYLOAD_SDK is unset and payloads/dispatcher.elf is missing.\n"
         "         the site will build but the chain will stop after elfldr.");
  }

  /* LICENSE ships with the deploy: AGPLv3 section 4/6 requires conveying the
   * licence and copyright notice with both source and object forms, and
   * section 13 wants the source reachable from wherever the site is served. */
  for (i = 0; files[i]; i++) {
    char dst[PATH_MAX];
    snprintf(dst, sizeof dst, "dist/%s", files[i]);
    install_file(files[i], dst, 0644);
  }
  for (i = 0; dirs[i]; i++) {
    char dst[PATH_MAX];
    snprintf(dst, sizeof dst, "dist/%s", dirs[i]);
    if (copy_tree(dirs[i], dst)) die("cannot copy %s into dist/", dirs[i]);
  }

  /* Unmistakable per-deploy tag, fixed to the bottom-left corner: the console
   * cannot open a URL easily, so the label proves which bundle is running.
   * The checked-in index.html stays clean; only dist/ gets the tag. */
  if ((idx = read_whole("dist/index.html", &idxlen))) {
    char *at = strstr(idx, BVER_OPEN);
    if (at) {
      size_t pre = (size_t)(at - idx);
      size_t post = idxlen - pre - strlen(BVER_OPEN);
      const char *sha = git_short_sha();
      size_t total_len = pre + strlen(BVER_OPEN) + strlen(sha) + post;
      char *out = malloc(total_len + 1);

      if (!out) die("out of memory");
      memcpy(out, idx, pre);
      memcpy(out + pre, BVER_OPEN, strlen(BVER_OPEN));
      memcpy(out + pre + strlen(BVER_OPEN), sha, strlen(sha));
      memcpy(out + pre + strlen(BVER_OPEN) + strlen(sha), at + strlen(BVER_OPEN), post);
      out[total_len] = '\0';
      FILE *f = fopen("dist/index.html", "wb");
      if (!f || fwrite(out, 1, total_len, f) != total_len)
        warn("cannot stamp build tag into dist/index.html");
      if (f) fclose(f);
      free(out);
    }
    free(idx);
  }

  puts("dist/ contents:");
  list_tree("dist", "dist", &total);
  printf("\ntotal: %s\n", human(total));
  return 0;
}