/* ClamShield's Exim API adapter. This is application glue, not an Exim fork.
 * Build against the Ubuntu exim4-dev headers. No scanner or mail policy lives
 * in this module. Do not enable before the durable mail policy service exists.
 */
#define _GNU_SOURCE
#define LOCAL_SCAN
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "local_scan.h"

#ifndef CS_SOCKET_PATH
#define CS_SOCKET_PATH "/run/clamshield-mail/policy.sock"
#endif
#define CS_METADATA_MAX (128 * 1024)
#define CS_MESSAGE_MAX (64 * 1024 * 1024)
#define CS_HEADERS_MAX (1024 * 1024)
#define CS_RECIPIENTS_MAX 1000
#ifndef CS_TIMEOUT_SECONDS
#define CS_TIMEOUT_SECONDS 30
#endif

int local_scan_version_major(void) { return LOCAL_SCAN_ABI_VERSION_MAJOR; }
int local_scan_version_minor(void) { return LOCAL_SCAN_ABI_VERSION_MINOR; }

static int write_all(int fd, const void *data, size_t size)
{
  const unsigned char *p = data;
  while (size) {
    ssize_t n = write(fd, p, size);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    p += n;
    size -= (size_t)n;
  }
  return 0;
}

/* pread leaves Exim's spool descriptor and body bytes unchanged. */
static int message_snapshot(int body)
{
  struct stat before, after;
  off_t offset = lseek(body, 0, SEEK_CUR);
  if (offset < 0 || fstat(body, &before) || !S_ISREG(before.st_mode) ||
      before.st_size < offset || before.st_size - offset > CS_MESSAGE_MAX)
    return -1;
  int out = memfd_create("clamshield-mail", MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (out < 0) return -1;
  size_t headers = 0;
  for (header_line *h = header_list; h; h = h->next) {
    if (h->type == '*') continue;
    if (h->slen < 0 || (size_t)h->slen > CS_HEADERS_MAX - headers ||
        !h->text || write_all(out, h->text, (size_t)h->slen)) goto fail;
    headers += (size_t)h->slen;
  }
  if (write_all(out, "\n", 1)) goto fail;
  unsigned char buffer[65536];
  off_t at = offset;
  while (at < before.st_size) {
    size_t want = (size_t)(before.st_size - at);
    if (want > sizeof(buffer)) want = sizeof(buffer);
    ssize_t n = pread(body, buffer, want, at);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0 || write_all(out, buffer, (size_t)n)) goto fail;
    at += n;
  }
  if (fstat(body, &after) || before.st_dev != after.st_dev ||
      before.st_ino != after.st_ino || before.st_size != after.st_size ||
      before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
      before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
      before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
      before.st_ctim.tv_nsec != after.st_ctim.tv_nsec ||
      fcntl(out, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
            F_SEAL_SEAL) || lseek(out, 0, SEEK_SET) < 0) goto fail;
  return out;
fail:
  close(out);
  return -1;
}

static int append_string(unsigned char *buffer, size_t *used,
                         const unsigned char *value, size_t limit)
{
  size_t size = value ? strnlen((const char *)value, limit + 1) : 0;
  if (size > limit || size + 4 > CS_METADATA_MAX - *used) return -1;
  uint32_t length = htonl((uint32_t)size);
  memcpy(buffer + *used, &length, 4);
  *used += 4;
  if (size) memcpy(buffer + *used, value, size);
  *used += size;
  return 0;
}

/* Only validated recipient indexes and fixed class groups enter an expansion.
 * The owned ACL maps them to Exim's own envelope; no address/header text is
 * interpolated into the expression. ACL message variables survive queueing. */
static int fallback_subject_marks(const unsigned char *tags, uint32_t count)
{
  char command[CS_RECIPIENTS_MAX * 5 + 128];
  size_t used = (size_t)snprintf(command, sizeof(command),
                                "${acl{clamshield_fallback_mark}");
  for (unsigned int kind = 1; kind <= 4; ++kind) {
    if (used + 2 >= sizeof(command)) return -1;
    command[used++] = '{';
    int first = 1;
    for (uint32_t i = 0; i < count; ++i) {
      if (tags[i] != kind) continue;
      int n = snprintf(command + used, sizeof(command) - used,
                       "%s%u", first ? "" : ":", i + 1);
      if (n < 0 || (size_t)n >= sizeof(command) - used) return -1;
      used += (size_t)n; first = 0;
    }
    if (used + 2 >= sizeof(command)) return -1;
    command[used++] = '}';
  }
  command[used++] = '}'; command[used] = '\0';
  uschar *result = expand_string(US command);
  return result && !strcmp((const char *)result,
                           "clamshield-fallback-marked-v1") ? 0 : -1;
}

int local_scan(int body, uschar **return_text)
{
  int out = -1, connection = -1, result = LOCAL_SCAN_ACCEPT, fallback = 1;
  unsigned char *request = NULL;
  *return_text = US"ClamShield mail check unavailable; please retry";
  if (recipients_count < 1 || recipients_count > CS_RECIPIENTS_MAX) goto done;
  request = malloc(CS_METADATA_MAX);
  if (!request) goto done;
  memcpy(request, "CSMAIL05", 8);
  uint32_t count = htonl((uint32_t)recipients_count);
  uint32_t flags = htonl((smtp_input ? 1u : 0u) | (smtp_batched_input ? 2u : 0u));
  memcpy(request + 8, &count, 4);
  memcpy(request + 12, &flags, 4);
  size_t used = 16;
  const uschar *authenticated = expand_string(US"$authenticated_id");
  /* Exim's own content-scanning variable, never an RFC822 status header.
   * An empty value means native SpamAssassin did not produce a score. */
  const uschar *native_spam_score = expand_string(US"$spam_score_int");
  /* Only Exim ACL variables are authoritative. Never read sender-supplied
   * RFC822 headers as native reputation evidence. Unset ACL fields are empty. */
  const uschar *native_dnsbl_zone = expand_string(US"$acl_m_clamshield_dnsbl_zone");
  const uschar *native_dnsbl_value = expand_string(US"$acl_m_clamshield_dnsbl_value");
  const uschar *native_mime_blocked = expand_string(US"$acl_m_clamshield_mime_blocked");
  if (!authenticated ||
      append_string(request, &used, message_id, 128) ||
      append_string(request, &used, sender_address, 1024) ||
      append_string(request, &used, sender_host_address, 128) ||
      append_string(request, &used, authenticated, 1024) ||
      append_string(request, &used, received_protocol, 64) ||
      append_string(request, &used, native_spam_score, 32) ||
      append_string(request, &used, native_dnsbl_zone, 256) ||
      append_string(request, &used, native_dnsbl_value, 2048) ||
      append_string(request, &used, native_mime_blocked, 1)) goto done;
  for (int i = 0; i < recipients_count; ++i)
    if (append_string(request, &used, recipients_list[i].address, 1024)) goto done;
  out = message_snapshot(body);
  if (out < 0) goto done;
  connection = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (connection < 0) goto done;
  struct timeval timeout = {.tv_sec = CS_TIMEOUT_SECONDS, .tv_usec = 0};
  if (setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
      setsockopt(connection, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) goto done;
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  if (sizeof(CS_SOCKET_PATH) > sizeof(address.sun_path)) goto done;
  memcpy(address.sun_path, CS_SOCKET_PATH, sizeof(CS_SOCKET_PATH));
  if (connect(connection, (struct sockaddr *)&address, sizeof(address))) goto done;
  /* Only a root-owned policy service may issue a decision. */
  struct ucred credentials;
  socklen_t length = sizeof(credentials);
  if (getsockopt(connection, SOL_SOCKET, SO_PEERCRED, &credentials, &length) ||
      length != sizeof(credentials) || credentials.uid != 0) goto done;
  union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
  memset(&control, 0, sizeof(control));
  struct iovec vector = {.iov_base = request, .iov_len = used};
  struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
                          .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
  struct cmsghdr *c = CMSG_FIRSTHDR(&message);
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(c), &out, sizeof(int));
  ssize_t sent;
  do { sent = sendmsg(connection, &message, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
  if (sent < 0 || (size_t)sent != used) goto done;
  unsigned char response[49 + CS_RECIPIENTS_MAX];
  ssize_t received;
  do { received = recv(connection, response, sizeof(response), 0); }
  while (received < 0 && errno == EINTR);
  if (received < 44 || memcmp(response, "CSMRSP01", 8)) goto done;
  uint32_t decision;
  memcpy(&decision, response + 8, 4);
  decision = ntohl(decision);
  if (decision > 6 || (decision != 4 && decision != 6 && received != 44)) goto done;
  if (decision == 4 || decision == 6) {
    if (received < 48) goto done;
    uint32_t count;
    memcpy(&count, response + 44, 4);
    count = ntohl(count);
    if (count != (uint32_t)recipients_count || received != 48 + (ssize_t)count) goto done;
    unsigned int selected = 0;
    for (uint32_t i = 0; i < count; ++i) {
      if (response[48 + i] > (decision == 4 ? 1 : 4)) goto done;
      selected += response[48 + i];
    }
    if (selected == 0 || (decision == 4 && selected == count)) goto done;
  }
  for (size_t i = 12; i < 44; ++i)
    if (!((response[i] >= '0' && response[i] <= '9') ||
          (response[i] >= 'a' && response[i] <= 'f'))) goto done;
  char event[33];
  memcpy(event, response + 12, 32);
  event[32] = '\0';
  log_write(0, LOG_MAIN, "ClamShield decision=%u event=%s", decision, event);
  fallback = decision == 5 || decision == 6;
  if (decision == 0) {
    *return_text = NULL;
    result = LOCAL_SCAN_ACCEPT;
  } else if (decision == 1) {
    *return_text = US"Message rejected by ClamShield policy";
    result = LOCAL_SCAN_REJECT_NOLOGHDR;
  } else if (decision == 2) {
    result = LOCAL_SCAN_TEMPREJECT_NOLOGHDR;
  } else if (decision == 3) {
    /* The policy service must durably own ALL recipients before returning this. */
    recipients_count = 0;
    *return_text = NULL;
    result = LOCAL_SCAN_ACCEPT;
  } else if (decision == 4) {
    /* Retain full native recipient metadata for every non-custody recipient. */
    int kept = 0;
    for (int i = 0; i < recipients_count; ++i)
      if (response[48 + i] == 0) recipients_list[kept++] = recipients_list[i];
    recipients_count = kept;
    *return_text = NULL;
    result = LOCAL_SCAN_ACCEPT;
  } else if (decision == 6) {
    if (fallback_subject_marks(response + 48, (uint32_t)recipients_count) == 0)
      log_write(0, LOG_MAIN, "ClamShield native fallback subject marking prepared");
    else
      log_write(0, LOG_MAIN, "ClamShield native fallback subject marking unavailable");
    /* No custody and no second submission. Every original recipient remains
     * native, including unmarked recipients of a mixed-policy envelope. */
  }
done:
  if (fallback) {
    /* No custody transfer was applied. Native Exim still owns every original
     * recipient and the spool. This is an incomplete check, never a clean scan.
     * An exact native log marker also prevents an uncertain broker capture
     * from later being committed and delivered a second time. */
    log_write(0, LOG_MAIN, "ClamShield native delivery fallback; check incomplete");
    *return_text = NULL;
  }
  if (connection >= 0) close(connection);
  if (out >= 0) close(out);
  free(request);
  return result;
}
