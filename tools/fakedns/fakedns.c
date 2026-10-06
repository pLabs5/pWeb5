// pWeb5 fakedns
//
//  C port of idlesauce/PS5-Exploit-Host's fakedns.py changed a bit for
//  this site, see the orginal at:
//        https://github.com/idlesauce/PS5-Exploit-Host/blob/main/fakedns.py
//  
// Everything else about the reference behavior (53/UDP responder, the
// override-or-forward sources) is preserved. Built by `make fakedns`.

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_PKT 4096

static volatile sig_atomic_t running = 1;
static void on_sig(int sig) { (void)sig; running = 0; }

static int contains_ci(const char *hay, const char *needle) {
  size_t nl = strlen(needle), hl = strlen(hay);
  if (!nl || nl > hl) return 0;
  for (size_t i = 0; i + nl <= hl; i++)
    if (strncasecmp(hay + i, needle, nl) == 0)
      return 1;
  return 0;
}

static int blocked_name(const char *name) {
  return contains_ci(name, "playstation") ||
         contains_ci(name, "sonyentertainmentnetwork") ||
         contains_ci(name, "scea");
}

// Dotted-form qname parse. Returns 0/-1.
static int parse_qname(const uint8_t *p, int n, char *out, int cap) {
  int i = 12, w = 0;
  while (i < n) {
    int l = p[i];
    if (l == 0) { out[w] = 0; return w > 0 ? 0 : -1; }
    if (l > 63 || i + 1 + l > n) return -1;
    i++;
    if (w) { out[w++] = '.'; if (w >= cap) return -1; }
    if (w + l >= cap) return -1;
    memcpy(out + w, p + i, (size_t)l);
    w += l; out[w] = 0;
    i += l;
  }
  return -1;
}

// Length of the entire question section in the query.
static int qlen(const uint8_t *p, int n) {
  int i = 12;
  while (i < n) {
    int l = p[i];
    if (l == 0) return (i + 1 - 12) + 4;
    if (l > 63) return 0;
    i += l + 1;
  }
  return 0;
}

// Build a raw "kind NONEFOUND" packet, like the original's NONEFOUND:
// no answers, NXDOMAIN rcode, question echoed.
static int pkt_nxdomain(const uint8_t *in, int inlen, uint8_t *out, int outcap) {
  int q = qlen(in, inlen);
  if (q <= 0 || 12 + q > outcap) return -1;

  memcpy(out, in, 12);
  out[0] = in[0]; out[1] = in[1];      // transaction ID
  out[2] = 0x81; out[3] = 0x83;        // QR, RD, RA, RCODE=nxdomain
  out[4] = 0;    out[5] = 1;           // qd=1
  out[6] = 0;    out[7] = 0;           // an=0
  out[8] = 0;    out[9] = 0;           // ns=0
  out[10] = 0;   out[11] = 0;          // ar=0
  memcpy(out + 12, in + 12, (size_t)q);
  return 12 + q;
}

// Build the manuals.playstation.com A record answer of the original's shape:
// question echo + pointer 0xC00C + A/IN + ttl + RDLENGTH + IPv4.
static int pkt_manual_redirect(const uint8_t *in, int inlen,
                               const struct in_addr *a,
                               uint8_t *out, int outcap) {
  int q = qlen(in, inlen);
  if (q <= 0 || 12 + q + 16 > outcap) return -1;

  memcpy(out, in, 12);
  out[0] = in[0]; out[1] = in[1];
  out[2] = 0x81; out[3] = 0x80;        // QR, RA, RCODE=no error
  out[4] = 0;    out[5] = 1;           // qd=1
  out[6] = 0;    out[7] = 1;           // an=1
  out[8] = 0;    out[9] = 0;
  out[10] = 0;   out[11] = 0;
  memcpy(out + 12, in + 12, (size_t)q);
  out += 12 + q;
  out[0] = 0xc0; out[1] = 0x0c;        // name pointer → question name
  out[2] = 0;    out[3] = 1;           // type A
  out[4] = 0;    out[5] = 1;           // class IN
  out[6] = 0; out[7] = 0; out[8] = 0; out[9] = 1; // ttl = 1
  out[10] = 0;  out[11] = 4;           // rdlength
  memcpy(out + 12, &a->s_addr, 4);
  return 12 + q + 16;
}

static uint32_t ip_of(const char *host) {
  struct addrinfo hints, *res = NULL;
  uint32_t out = 0;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    out = sin->sin_addr.s_addr;
    freeaddrinfo(res);
  }
  return out;
}

static void allow_firewall_udp53(const char *ps5) {
  if (geteuid() == 0) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iptables -I INPUT -s %s -p udp --dport 53 -j ACCEPT 2>/dev/null", ps5);
    if (system(cmd) != 0) { /* whatever; we still try the simple one */ }
    fputs("[fakedns] firewall: udp/53 permitted\n", stderr);
  } else {
    fputs("[fakedns] firewall: to allow port 53 from the PS5, run:\n", stderr);
    fprintf(stderr, "         sudo iptables -I INPUT -s %s -p udp --dport 53 -j ACCEPT\n", ps5);
  }
}

int main(int argc, char **argv) {
  const char *ps5 = NULL;
  const char *upstream = "8.8.8.8";
  const char *redirect_target = "pweb5.pages.dev";
  int port = 53;
  int user_guide = 1, ps_blocking = 1, do_forward = 1;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--ps5") && i + 1 < argc) ps5 = argv[++i];
    else if (!strcmp(argv[i], "--upstream") && i + 1 < argc) upstream = argv[++i];
    else if (!strcmp(argv[i], "--redirect") && i + 1 < argc) redirect_target = argv[++i];
    else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--no-user-guide")) user_guide = 0;
    else if (!strcmp(argv[i], "--no-ps-blocking")) ps_blocking = 0;
    else if (!strcmp(argv[i], "--noforward")) do_forward = 0;
    else if (!strcmp(argv[i], "--help")) {
      fputs("usage: fakedns --ps5 <ip> [--upstream ip] [--redirect host] [--port N]\n"
            "              [--no-ps-blocking] [--no-user-guide] [--noforward]\n", stderr);
      return 0;
    }
  }
  if (!ps5) {
    fputs("usage: fakedns --ps5 <ip>\n", stderr);
    return 2;
  }

  signal(SIGINT, on_sig);
  signal(SIGTERM, on_sig);

  // The IP we would dial out from when we reach the PS5 is our own address on
  // that link; the console should use it as its resolver.
  char local[INET_ADDRSTRLEN] = "?";
  int probe = socket(AF_INET, SOCK_DGRAM, 0);
  if (probe >= 0) {
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(53) };
    if (inet_pton(AF_INET, ps5, &dst.sin_addr) == 1 &&
        connect(probe, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
      struct sockaddr_in me = { .sin_family = AF_INET };
      socklen_t mn = sizeof(me);
      if (getsockname(probe, (struct sockaddr *)&me, &mn) == 0)
        inet_ntop(AF_INET, &me.sin_addr, local, sizeof(local));
    }
    close(probe);
  }

  uint32_t redirect_ip = ip_of(redirect_target);
  struct in_addr redaddr = {0};
  char redtext[INET_ADDRSTRLEN] = "unresolvable";
  if (redirect_ip) {
    redaddr.s_addr = redirect_ip;
    inet_ntop(AF_INET, &redaddr, redtext, sizeof(redtext));
  }

  fprintf(stderr, "[fakedns] local IP: %s\n", local);
  fprintf(stderr, "[fakedns] PS5 IP:   %s\n", ps5);
  fprintf(stderr, "[fakedns] manuals.playstation.com -> pweb5.pages.dev (%s)\n", redtext);
  allow_firewall_udp53(ps5);
  fprintf(stderr, "[fakedns] blocked substrings: playstation / sonyentertainmentnetwork / scea\n");
  fprintf(stderr, "[fakedns] will relay everything else to %s:53\n", upstream);

  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) { perror("socket"); return 1; }
  struct sockaddr_in bend = { .sin_family = AF_INET, .sin_port = htons(port) };
  bend.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(s, (struct sockaddr *)&bend, sizeof(bend)) < 0) {
    perror("bind");
    fprintf(stderr, "[fakedns] needs root to bind :53 - sudo ./tools/fakedns/fakedns --ps5 %s\n", ps5);
    return 1;
  }

  int up = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in usrv = { .sin_family = AF_INET, .sin_port = htons(53) };
  if (inet_pton(AF_INET, upstream, &usrv.sin_addr) != 1) {
    fprintf(stderr, "[fakedns] bad --upstream %s\n", upstream);
    return 2;
  }
  struct timeval tv = {5, 0};
  setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  uint8_t buf[MAX_PKT];
  while (running) {
    struct sockaddr_in src;
    socklen_t sr = sizeof(src);
    int n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&src, &sr);
    if (n < 12) continue;

    char name[256] = {0};
    if (parse_qname(buf, n, name, sizeof(name)) != 0) continue;

    // manual redirect first, so the block-list's playstation rule does not
    // swallow it; referent behavior in the original is the same order.
    if (user_guide && contains_ci(name, "manuals.playstation")) {
      if (redirect_ip) {
        uint8_t resp[MAX_PKT] = {0};
        int w = pkt_manual_redirect(buf, n, &redaddr, resp, sizeof(resp));
        if (w > 0) sendto(s, resp, (size_t)w, 0, (struct sockaddr *)&src, sr);
        fprintf(stderr, "[fakedns]     redirect: %s -> %s\n", name, redtext);
      } else {
        uint8_t resp[MAX_PKT] = {0};
        int w = pkt_nxdomain(buf, n, resp, sizeof(resp));
        if (w > 0) sendto(s, resp, w, 0, (struct sockaddr *)&src, sr);
        fprintf(stderr, "[fakedns]     redirect target unresolvable, NXDOMAIN for %s\n", name);
      }
      continue;
    }

    if (ps_blocking && blocked_name(name)) {
      uint8_t resp[MAX_PKT] = {0};
      int w = pkt_nxdomain(buf, n, resp, sizeof(resp));
      if (w > 0) sendto(s, resp, w, 0, (struct sockaddr *)&src, sr);
      fprintf(stderr, "[fakedns]     blocked: %s -> NXDOMAIN\n", name);
      continue;
    }

    if (do_forward && sendto(up, buf, n, 0, (struct sockaddr *)&usrv, sizeof(usrv)) == n) {
      uint8_t rep[4096];
      int rn2 = recvfrom(up, rep, sizeof(rep), 0, NULL, NULL);
      if (rn2 > 0) sendto(s, rep, rn2, 0, (struct sockaddr *)&src, sr);
      continue;
    }

    uint8_t resp[MAX_PKT] = {0};
    int w = pkt_nxdomain(buf, n, resp, sizeof(resp));
    if (w > 0) sendto(s, resp, w, 0, (struct sockaddr *)&src, sr);
    fprintf(stderr, "[fakedns]     not forwarded: %s -> NXDOMAIN\n", name);
  }
  close(s);
  close(up);
  return 0;
}
