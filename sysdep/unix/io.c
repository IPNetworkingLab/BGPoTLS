/*
 *	BIRD Internet Routing Daemon -- Unix I/O
 *
 *	(c) 1998--2004 Martin Mares <mj@ucw.cz>
 *      (c) 2004       Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/* Unfortunately, some glibc versions hide parts of RFC 3542 API
   if _GNU_SOURCE is not defined. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/string.h"
#include "nest/iface.h"
#include "conf/conf.h"

#include <picotls.h>

#include "sysdep/unix/unix.h"
#include CONFIG_INCLUDE_SYSIO_H
#include "tls_helpers.h"

/* Maximum number of calls of tx handler for one socket in one
 * poll iteration. Should be small enough to not monopolize CPU by
 * one protocol instance.
 */
#define MAX_STEPS 4

/* Maximum number of calls of rx handler for all sockets in one poll
   iteration. RX callbacks are often much more costly so we limit
   this to gen small latencies */
#define MAX_RX_STEPS 4


/*
 *	Tracked Files
 */

struct rfile {
  resource r;
  FILE *f;
};

static void
rf_free(resource *r)
{
  struct rfile *a = (struct rfile *) r;

  fclose(a->f);
}

static void
rf_dump(resource *r)
{
  struct rfile *a = (struct rfile *) r;

  debug("(FILE *%p)\n", a->f);
}

static struct resclass rf_class = {
  "FILE",
  sizeof(struct rfile),
  rf_free,
  rf_dump,
  NULL,
  NULL
};

struct rfile *
rf_open(pool *p, const char *name, const char *mode)
{
  FILE *f = fopen(name, mode);

  if (!f)
    return NULL;

  struct rfile *r = ralloc(p, &rf_class);
  r->f = f;
  return r;
}

void *
rf_file(struct rfile *f)
{
  return f->f;
}

int
rf_fileno(struct rfile *f)
{
  return fileno(f->f);
}


/*
 *	Time clock
 */

btime boot_time;

void
times_init(struct timeloop *loop)
{
  struct timespec ts;
  int rv;

  rv = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (rv < 0)
    die("Monotonic clock is missing");

  if ((ts.tv_sec < 0) || (((u64) ts.tv_sec) > ((u64) 1 << 40)))
    log(L_WARN "Monotonic clock is crazy");

  loop->last_time = ts.tv_sec S + ts.tv_nsec NS;
  loop->real_time = 0;
}

void
times_update(struct timeloop *loop)
{
  struct timespec ts;
  int rv;

  rv = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (rv < 0)
    die("clock_gettime: %m");

  btime new_time = ts.tv_sec S + ts.tv_nsec NS;

  if (new_time < loop->last_time)
    log(L_ERR "Monotonic clock is broken");

  loop->last_time = new_time;
  loop->real_time = 0;
}

void
times_update_real_time(struct timeloop *loop)
{
  struct timespec ts;
  int rv;

  rv = clock_gettime(CLOCK_REALTIME, &ts);
  if (rv < 0)
    die("clock_gettime: %m");

  loop->real_time = ts.tv_sec S + ts.tv_nsec NS;
}

btime
current_time_now(void)
{
  struct timespec ts;
  int rv;

  rv = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (rv < 0)
    die("clock_gettime: %m");

  return ts.tv_sec S + ts.tv_nsec NS;
}


/**
 * DOC: Sockets
 *
 * Socket resources represent network connections. Their data structure (&socket)
 * contains a lot of fields defining the exact type of the socket, the local and
 * remote addresses and ports, pointers to socket buffers and finally pointers to
 * hook functions to be called when new data have arrived to the receive buffer
 * (@rx_hook), when the contents of the transmit buffer have been transmitted
 * (@tx_hook) and when an error or connection close occurs (@err_hook).
 *
 * Freeing of sockets from inside socket hooks is perfectly safe.
 */

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef SOL_ICMPV6
#define SOL_ICMPV6 IPPROTO_ICMPV6
#endif


/*
 *	Sockaddr helper functions
 */

static inline int UNUSED sockaddr_length(int af)
{ return (af == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6); }

static inline void
sockaddr_fill4(struct sockaddr_in *sa, ip_addr a, uint port)
{
  memset(sa, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
  sa->sin_len = sizeof(struct sockaddr_in);
#endif
  sa->sin_family = AF_INET;
  sa->sin_port = htons(port);
  sa->sin_addr = ipa_to_in4(a);
}

static inline void
sockaddr_fill6(struct sockaddr_in6 *sa, ip_addr a, struct iface *ifa, uint port)
{
  memset(sa, 0, sizeof(struct sockaddr_in6));
#ifdef SIN6_LEN
  sa->sin6_len = sizeof(struct sockaddr_in6);
#endif
  sa->sin6_family = AF_INET6;
  sa->sin6_port = htons(port);
  sa->sin6_flowinfo = 0;
  sa->sin6_addr = ipa_to_in6(a);

  if (ifa && ipa_is_link_local(a))
    sa->sin6_scope_id = ifa->index;
}

void
sockaddr_fill(sockaddr *sa, int af, ip_addr a, struct iface *ifa, uint port)
{
  if (af == AF_INET)
    sockaddr_fill4((struct sockaddr_in *) sa, a, port);
  else if (af == AF_INET6)
    sockaddr_fill6((struct sockaddr_in6 *) sa, a, ifa, port);
  else
    bug("Unknown AF");
}

static inline void
sockaddr_read4(struct sockaddr_in *sa, ip_addr *a, uint *port)
{
  *port = ntohs(sa->sin_port);
  *a = ipa_from_in4(sa->sin_addr);
}

static inline void
sockaddr_read6(struct sockaddr_in6 *sa, ip_addr *a, struct iface **ifa, uint *port)
{
  *port = ntohs(sa->sin6_port);
  *a = ipa_from_in6(sa->sin6_addr);

  if (ifa && ipa_is_link_local(*a))
    *ifa = if_find_by_index(sa->sin6_scope_id);
}

int
sockaddr_read(sockaddr *sa, int af, ip_addr *a, struct iface **ifa, uint *port)
{
  if (sa->sa.sa_family != af)
    goto fail;

  if (af == AF_INET)
    sockaddr_read4((struct sockaddr_in *) sa, a, port);
  else if (af == AF_INET6)
    sockaddr_read6((struct sockaddr_in6 *) sa, a, ifa, port);
  else
    goto fail;

  return 0;

 fail:
  *a = IPA_NONE;
  *port = 0;
  return -1;
}


/*
 *	IPv6 multicast syscalls
 */

/* Fortunately standardized in RFC 3493 */

#define INIT_MREQ6(maddr,ifa) \
  { .ipv6mr_multiaddr = ipa_to_in6(maddr), .ipv6mr_interface = ifa->index }

static inline int
sk_setup_multicast6(sock *s)
{
  int index = s->iface->index;
  int ttl = s->ttl;
  int n = 0;

  if (setsockopt(s->fd, SOL_IPV6, IPV6_MULTICAST_IF, &index, sizeof(index)) < 0)
    ERR("IPV6_MULTICAST_IF");

  if (setsockopt(s->fd, SOL_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) < 0)
    ERR("IPV6_MULTICAST_HOPS");

  if (setsockopt(s->fd, SOL_IPV6, IPV6_MULTICAST_LOOP, &n, sizeof(n)) < 0)
    ERR("IPV6_MULTICAST_LOOP");

  return 0;
}

static inline int
sk_join_group6(sock *s, ip_addr maddr)
{
  struct ipv6_mreq mr = INIT_MREQ6(maddr, s->iface);

  if (setsockopt(s->fd, SOL_IPV6, IPV6_JOIN_GROUP, &mr, sizeof(mr)) < 0)
    ERR("IPV6_JOIN_GROUP");

  return 0;
}

static inline int
sk_leave_group6(sock *s, ip_addr maddr)
{
  struct ipv6_mreq mr = INIT_MREQ6(maddr, s->iface);

  if (setsockopt(s->fd, SOL_IPV6, IPV6_LEAVE_GROUP, &mr, sizeof(mr)) < 0)
    ERR("IPV6_LEAVE_GROUP");

  return 0;
}


/*
 *	IPv6 packet control messages
 */

/* Also standardized, in RFC 3542 */

/*
 * RFC 2292 uses IPV6_PKTINFO for both the socket option and the cmsg
 * type, RFC 3542 changed the socket option to IPV6_RECVPKTINFO. If we
 * don't have IPV6_RECVPKTINFO we suppose the OS implements the older
 * RFC and we use IPV6_PKTINFO.
 */
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif
/*
 * Same goes for IPV6_HOPLIMIT -> IPV6_RECVHOPLIMIT.
 */
#ifndef IPV6_RECVHOPLIMIT
#define IPV6_RECVHOPLIMIT IPV6_HOPLIMIT
#endif


#define CMSG6_SPACE_PKTINFO CMSG_SPACE(sizeof(struct in6_pktinfo))
#define CMSG6_SPACE_TTL CMSG_SPACE(sizeof(int))

static inline int
sk_request_cmsg6_pktinfo(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, SOL_IPV6, IPV6_RECVPKTINFO, &y, sizeof(y)) < 0)
    ERR("IPV6_RECVPKTINFO");

  return 0;
}

static inline int
sk_request_cmsg6_ttl(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, SOL_IPV6, IPV6_RECVHOPLIMIT, &y, sizeof(y)) < 0)
    ERR("IPV6_RECVHOPLIMIT");

  return 0;
}

static inline void
sk_process_cmsg6_pktinfo(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IPV6_PKTINFO)
  {
    struct in6_pktinfo *pi = (struct in6_pktinfo *) CMSG_DATA(cm);
    s->laddr = ipa_from_in6(pi->ipi6_addr);
    s->lifindex = pi->ipi6_ifindex;
  }
}

static inline void
sk_process_cmsg6_ttl(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IPV6_HOPLIMIT)
    s->rcv_ttl = * (int *) CMSG_DATA(cm);
}

static inline void
sk_prepare_cmsgs6(sock *s, struct msghdr *msg, void *cbuf, size_t cbuflen)
{
  struct cmsghdr *cm;
  struct in6_pktinfo *pi;
  int controllen = 0;

  msg->msg_control = cbuf;
  msg->msg_controllen = cbuflen;

  cm = CMSG_FIRSTHDR(msg);
  cm->cmsg_level = SOL_IPV6;
  cm->cmsg_type = IPV6_PKTINFO;
  cm->cmsg_len = CMSG_LEN(sizeof(*pi));
  controllen += CMSG_SPACE(sizeof(*pi));

  pi = (struct in6_pktinfo *) CMSG_DATA(cm);
  pi->ipi6_ifindex = s->iface ? s->iface->index : 0;
  pi->ipi6_addr = ipa_to_in6(s->saddr);

  msg->msg_controllen = controllen;
}


/*
 *	Miscellaneous socket syscalls
 */

static inline int
sk_set_ttl4(sock *s, int ttl)
{
  if (setsockopt(s->fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
    ERR("IP_TTL");

  return 0;
}

static inline int
sk_set_ttl6(sock *s, int ttl)
{
  if (setsockopt(s->fd, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0)
    ERR("IPV6_UNICAST_HOPS");

  return 0;
}

static inline int
sk_set_tos4(sock *s, int tos)
{
  if (setsockopt(s->fd, SOL_IP, IP_TOS, &tos, sizeof(tos)) < 0)
    ERR("IP_TOS");

  return 0;
}

static inline int
sk_set_tos6(sock *s, int tos)
{
  if (setsockopt(s->fd, SOL_IPV6, IPV6_TCLASS, &tos, sizeof(tos)) < 0)
    ERR("IPV6_TCLASS");

  return 0;
}

static inline int
sk_set_high_port(sock *s UNUSED)
{
  /* Port range setting is optional, ignore it if not supported */

#ifdef IP_PORTRANGE
  if (sk_is_ipv4(s))
  {
    int range = IP_PORTRANGE_HIGH;
    if (setsockopt(s->fd, SOL_IP, IP_PORTRANGE, &range, sizeof(range)) < 0)
      ERR("IP_PORTRANGE");
  }
#endif

#ifdef IPV6_PORTRANGE
  if (sk_is_ipv6(s))
  {
    int range = IPV6_PORTRANGE_HIGH;
    if (setsockopt(s->fd, SOL_IPV6, IPV6_PORTRANGE, &range, sizeof(range)) < 0)
      ERR("IPV6_PORTRANGE");
  }
#endif

  return 0;
}

static inline byte *
sk_skip_ip_header(byte *pkt, int *len)
{
  if ((*len < 20) || ((*pkt & 0xf0) != 0x40))
    return NULL;

  int hlen = (*pkt & 0x0f) * 4;
  if ((hlen < 20) || (hlen > *len))
    return NULL;

  *len -= hlen;
  return pkt + hlen;
}

byte *
sk_rx_buffer(sock *s, int *len)
{
  if (sk_is_ipv4(s) && (s->type == SK_IP))
    return sk_skip_ip_header(s->rbuf, len);
  else
    return s->rbuf;
}


/*
 *	Public socket functions
 */

/**
 * sk_setup_multicast - enable multicast for given socket
 * @s: socket
 *
 * Prepare transmission of multicast packets for given datagram socket.
 * The socket must have defined @iface.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_setup_multicast(sock *s)
{
  ASSERT(s->iface);

  if (sk_is_ipv4(s))
    return sk_setup_multicast4(s);
  else
    return sk_setup_multicast6(s);
}

/**
 * sk_join_group - join multicast group for given socket
 * @s: socket
 * @maddr: multicast address
 *
 * Join multicast group for given datagram socket and associated interface.
 * The socket must have defined @iface.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_join_group(sock *s, ip_addr maddr)
{
  if (sk_is_ipv4(s))
    return sk_join_group4(s, maddr);
  else
    return sk_join_group6(s, maddr);
}

/**
 * sk_leave_group - leave multicast group for given socket
 * @s: socket
 * @maddr: multicast address
 *
 * Leave multicast group for given datagram socket and associated interface.
 * The socket must have defined @iface.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_leave_group(sock *s, ip_addr maddr)
{
  if (sk_is_ipv4(s))
    return sk_leave_group4(s, maddr);
  else
    return sk_leave_group6(s, maddr);
}

/**
 * sk_setup_broadcast - enable broadcast for given socket
 * @s: socket
 *
 * Allow reception and transmission of broadcast packets for given datagram
 * socket. The socket must have defined @iface. For transmission, packets should
 * be send to @brd address of @iface.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_setup_broadcast(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, SOL_SOCKET, SO_BROADCAST, &y, sizeof(y)) < 0)
    ERR("SO_BROADCAST");

  return 0;
}

/**
 * sk_set_ttl - set transmit TTL for given socket
 * @s: socket
 * @ttl: TTL value
 *
 * Set TTL for already opened connections when TTL was not set before. Useful
 * for accepted connections when different ones should have different TTL.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_set_ttl(sock *s, int ttl)
{
  s->ttl = ttl;

  if (sk_is_ipv4(s))
    return sk_set_ttl4(s, ttl);
  else
    return sk_set_ttl6(s, ttl);
}

/**
 * sk_set_min_ttl - set minimal accepted TTL for given socket
 * @s: socket
 * @ttl: TTL value
 *
 * Set minimal accepted TTL for given socket. Can be used for TTL security.
 * implementations.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_set_min_ttl(sock *s, int ttl)
{
  if (sk_is_ipv4(s))
    return sk_set_min_ttl4(s, ttl);
  else
    return sk_set_min_ttl6(s, ttl);
}

#if 0
/**
 * sk_set_md5_auth - add / remove MD5 security association for given socket
 * @s: socket
 * @local: IP address of local side
 * @remote: IP address of remote side
 * @ifa: Interface for link-local IP address
 * @passwd: Password used for MD5 authentication
 * @setkey: Update also system SA/SP database
 *
 * In TCP MD5 handling code in kernel, there is a set of security associations
 * used for choosing password and other authentication parameters according to
 * the local and remote address. This function is useful for listening socket,
 * for active sockets it may be enough to set s->password field.
 *
 * When called with passwd != NULL, the new pair is added,
 * When called with passwd == NULL, the existing pair is removed.
 *
 * Note that while in Linux, the MD5 SAs are specific to socket, in BSD they are
 * stored in global SA/SP database (but the behavior also must be enabled on
 * per-socket basis). In case of multiple sockets to the same neighbor, the
 * socket-specific state must be configured for each socket while global state
 * just once per src-dst pair. The @setkey argument controls whether the global
 * state (SA/SP database) is also updated.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_set_md5_auth(sock *s, ip_addr local, ip_addr remote, struct iface *ifa, char *passwd, int setkey)
{ DUMMY; }
#endif

/**
 * sk_set_ipv6_checksum - specify IPv6 checksum offset for given socket
 * @s: socket
 * @offset: offset
 *
 * Specify IPv6 checksum field offset for given raw IPv6 socket. After that, the
 * kernel will automatically fill it for outgoing packets and check it for
 * incoming packets. Should not be used on ICMPv6 sockets, where the position is
 * known to the kernel.
 *
 * Result: 0 for success, -1 for an error.
 */

int
sk_set_ipv6_checksum(sock *s, int offset)
{
  if (setsockopt(s->fd, SOL_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) < 0)
    ERR("IPV6_CHECKSUM");

  return 0;
}

int
sk_set_icmp6_filter(sock *s, int p1, int p2)
{
  /* a bit of lame interface, but it is here only for Radv */
  struct icmp6_filter f;

  ICMP6_FILTER_SETBLOCKALL(&f);
  ICMP6_FILTER_SETPASS(p1, &f);
  ICMP6_FILTER_SETPASS(p2, &f);

  if (setsockopt(s->fd, SOL_ICMPV6, ICMP6_FILTER, &f, sizeof(f)) < 0)
    ERR("ICMP6_FILTER");

  return 0;
}

void
sk_log_error(sock *s, const char *p)
{
  log(L_ERR "%s: Socket error: %s%#m", p, s->err);
}


int sk_set_tls_cert(sock *s, const char *cert_location) {
    return tls_set_certs(&s->tls_ctx, s->certs,
                         sizeof(s->certs)/sizeof(s->certs[0]), cert_location);
}

int sk_set_tls_private_key(sock *s, const char *pkey_location) {
    return tls_set_pkey(&s->tls_ctx,
                        pkey_location,
                        s->tls_sign_obj,
                        sizeof(s->tls_sign_obj)/sizeof(s->tls_sign_obj[0]));
}

int sk_set_alpn(sock *s, const char *alpn, size_t alpn_len) {
    return tls_set_alpn(s->tls->tls, alpn, alpn_len);
}

int sk_set_peer_sni(sock *s, const char *sni, size_t sni_len) {
    return ptls_set_server_name(s->tls->tls, sni, sni_len);
}

int sk_get_remote_cert(sock *s, char **const cert, size_t *len) {
    return tls_get_remote_cert(s->tls, cert, len);
}

int sk_set_root_ca(sock *s, const char *root_ca) {
    return tls_set_root_ca(&s->tls_ctx, s->tls_verif_obj,
                           sizeof(s->tls_verif_obj) / sizeof(s->tls_verif_obj[0]),
                           root_ca, &s->verif_x509_store);
}

int sk_local_cert_to_pem(sock *s, char *pem_buf, size_t *pem_buf_len) {
    return tls_cert_to_pem(&s->certs[0], pem_buf, pem_buf_len);
}

int sk_set_export_key(sock *s, const char *export_file) {
    if (!export_file) return 0;
    return tls_setup_log_event(&s->tls_ctx, &s->log_evt, export_file);
}

int sk_set_per_tls_session_state(sock *s, const char *sni, size_t sni_len,
                             const char *alpn, size_t alpn_len, int is_server)  {

    assert(!s->tls);

    if ((s->tls = tls_ref_new(&s->tls_ctx, is_server)) == NULL)
        goto err;

    tls_set_verifier_ctx(s->tls_verif_obj, s->tls);

    if (sk_set_alpn(s, alpn, alpn_len) == -1)
        goto err;
    if (sk_set_peer_sni(s, sni, sni_len) == -1)
        goto err;

    return 0;
    err:
    return -1;
}

int sk_set_tls(sock *s, const char *cert_location, const char *pkey_location,
               const char *alpn, size_t alpn_len, const char *peer_sni,
               size_t peer_sni_len, const char *root_ca, const char *export_keys,
               const char *local_sni, size_t local_sni_len) {

    /* static int fd_log = -1; */

    if (s->type != SK_TLS_PASSIVE && s->type != SK_TLS_ACTIVE) {
        goto err;
    }
    if (s->tls) {
        fprintf(stderr, "TLS context already init !\n");
        if (!s->passive_sock) {
            fprintf(stderr, "Illegal state\n");
            goto err; // already init !
        } else  {
            tls_ref_inc(s->tls);
            return 0;
        }
    }

    tls_init(&s->tls_ctx);


    /*if (fd_log ==-1) {
        fd_log = open("/tmp/ptls.log", O_RDWR | O_CREAT | O_APPEND);
        if (fd_log == -1) {
            die("open");
        }
        ptls_log_add_fd(fd_log);
    }*/

    if (sk_set_tls_cert(s, cert_location) == -1)
        goto err;
    if (sk_set_tls_private_key(s,pkey_location) == -1)
        goto err;
    if (sk_set_root_ca(s, root_ca) == -1)
        goto err;
    if (sk_set_export_key(s, export_keys) == -1)
        goto err;

    if (s->type == SK_TLS_PASSIVE){
        s->tls_ctx.require_client_authentication = 1;
        s->tls = NULL; // make sure passive sockets do not have tls session state

        /* and that's it ! tls session state
         * will be initiated upon accept() */
        return 0;
    }

    if (sk_set_per_tls_session_state(s, peer_sni, peer_sni_len, alpn,
                                     alpn_len, s->type == SK_TLS_PASSIVE ? 1 : 0) == -1)
        goto err;

    return 0;
    err:
    return -1;
}

/*
 *	Actual struct birdsock code
 */

static list sock_list;
static struct birdsock *current_sock;
static struct birdsock *stored_sock;

static inline sock *
sk_next(sock *s)
{
  if (!s->n.next->next)
    return NULL;
  else
    return SKIP_BACK(sock, n, s->n.next);
}

static void
sk_alloc_bufs(sock *s)
{
  if (!s->rbuf && s->rbsize)
    s->rbuf = s->rbuf_alloc = xmalloc(s->rbsize);
  s->rpos = s->rbuf;
  if (!s->tbuf && s->tbsize)
    s->tbuf = s->tbuf_alloc = xmalloc(s->tbsize);
  s->tpos = s->ttx = s->tbuf;

  /* tls enabled socket */
  if (IS_SK_TLS(s->type)) {
      if (!s->encrypted_send_buf && s->tbsize) {
          s->encrypted_send_buf = xmalloc(s->tbsize * 2);
          s->encrypted_send_pos = s->encrypted_send_buf;
          s->encrypted_send_off = s->encrypted_send_buf;
          s->encrypted_send_buf_len = s->tbsize * 2;
          ptls_buffer_init(&s->sendbuf, s->encrypted_send_buf, s->tbsize * 2);
      }
      if (!s->recv_plain_txt && s->rbsize) {
          assert(s->rbsize);
          s->recv_plain_txt = xmalloc(MAX_MTU);
          s->recv_txt_pos = s->recv_plain_txt;
          s->recv_plain_txt_len = MAX_MTU;
          ptls_buffer_init(&s->recvbuf, s->rbuf, s->rbsize);
      }
  }
}

static void
sk_free_bufs(sock *s)
{
  if (s->rbuf_alloc)
  {
    xfree(s->rbuf_alloc);
    s->rbuf = s->rbuf_alloc = NULL;
  }
  if (s->tbuf_alloc)
  {
    xfree(s->tbuf_alloc);
    s->tbuf = s->tbuf_alloc = NULL;
  }
  if (IS_SK_TLS(s->type)) {
      if (s->encrypted_send_buf) {
          ptls_buffer_dispose(&s->sendbuf);
          xfree(s->encrypted_send_buf);
          s->encrypted_send_buf = NULL;
      }
      if (s->recv_plain_txt) {
          if (s->rbuf) ptls_buffer_dispose(&s->recvbuf);
          xfree(s->recv_plain_txt);
          s->recv_plain_txt = NULL;
          s->recv_plain_txt_len = 0;
      }
  }
}

#ifdef HAVE_LIBSSH
static void
sk_ssh_free(sock *s)
{
  struct ssh_sock *ssh = s->ssh;

  if (s->ssh == NULL)
    return;

  s->ssh = NULL;

  if (ssh->channel)
  {
    if (ssh_channel_is_open(ssh->channel))
      ssh_channel_close(ssh->channel);
    ssh_channel_free(ssh->channel);
    ssh->channel = NULL;
  }

  if (ssh->session)
  {
    ssh_disconnect(ssh->session);
    ssh_free(ssh->session);
    ssh->session = NULL;
  }
}
#endif

static void
sk_free(resource *r)
{
  sock *s = (sock *) r;

  sk_free_bufs(s);

#ifdef HAVE_LIBSSH
  if (s->type == SK_SSH || s->type == SK_SSH_ACTIVE)
    sk_ssh_free(s);
#endif

  if (s->tls) {
      tls_ref_dec(s->tls);
      s->tls = NULL;
  }

  if (s->verif_x509_store) {
      tls_free_verif_store(s->verif_x509_store);
      s->verif_x509_store = NULL;
  }

  if (s->fd < 0)
    return;

  /* FIXME: we should call sk_stop() for SKF_THREAD sockets */
  if (!(s->flags & SKF_THREAD))
  {
    if (s == current_sock)
      current_sock = sk_next(s);
    if (s == stored_sock)
      stored_sock = sk_next(s);
    rem_node(&s->n);
  }

  if (s->type != SK_SSH && s->type != SK_SSH_ACTIVE)
    close(s->fd);

  s->fd = -1;
}

void
sk_set_rbsize(sock *s, uint val)
{
  ASSERT(s->rbuf_alloc == s->rbuf);

  if (s->rbsize == val)
    return;

  s->rbsize = val;
  xfree(s->rbuf_alloc);
  s->rbuf_alloc = xmalloc(val);
  s->rpos = s->rbuf = s->rbuf_alloc;
}

void
sk_set_tbsize(sock *s, uint val)
{
  ASSERT(s->tbuf_alloc == s->tbuf);

  if (s->tbsize == val)
    return;

  byte *old_tbuf = s->tbuf;

  s->tbsize = val;
  s->tbuf = s->tbuf_alloc = xrealloc(s->tbuf_alloc, val);
  s->tpos = s->tbuf + (s->tpos - old_tbuf);
  s->ttx  = s->tbuf + (s->ttx  - old_tbuf);
}

void
sk_set_tbuf(sock *s, void *tbuf)
{
  s->tbuf = tbuf ?: s->tbuf_alloc;
  s->ttx = s->tpos = s->tbuf;
}

void
sk_reallocate(sock *s)
{
  sk_free_bufs(s);
  sk_alloc_bufs(s);
}

static void
sk_dump(resource *r)
{
  sock *s = (sock *) r;
  static char *sk_type_names[] = { "TCP<", "TCP>", "TCP", "UDP", NULL, "IP", NULL, "MAGIC", "UNIX<", "UNIX", "SSH>", "SSH", "DEL!" };

  debug("(%s, ud=%p, sa=%I, sp=%d, da=%I, dp=%d, tos=%d, ttl=%d, if=%s)\n",
	sk_type_names[s->type],
	s->data,
	s->saddr,
	s->sport,
	s->daddr,
	s->dport,
	s->tos,
	s->ttl,
	s->iface ? s->iface->name : "none");
}

static struct resclass sk_class = {
  "Socket",
  sizeof(sock),
  sk_free,
  sk_dump,
  NULL,
  NULL
};

/**
 * sk_new - create a socket
 * @p: pool
 *
 * This function creates a new socket resource. If you want to use it,
 * you need to fill in all the required fields of the structure and
 * call sk_open() to do the actual opening of the socket.
 *
 * The real function name is sock_new(), sk_new() is a macro wrapper
 * to avoid collision with OpenSSL.
 */
sock *
sock_new(pool *p)
{
  sock *s = ralloc(p, &sk_class);
  s->pool = p;
  // s->saddr = s->daddr = IPA_NONE;
  s->tos = s->priority = s->ttl = -1;
  s->fd = -1;
  return s;
}

static int
sk_setup(sock *s)
{
  int y = 1;
  int fd = s->fd;

  if (s->type == SK_SSH_ACTIVE)
    return 0;

  if (s->type == SK_UNIX_ACTIVE)
    return 0;

  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    ERR("O_NONBLOCK");

  if (!s->af)
    return 0;

  if (ipa_nonzero(s->saddr) && !(s->flags & SKF_BIND))
    s->flags |= SKF_PKTINFO;

#ifdef CONFIG_USE_HDRINCL
  if (sk_is_ipv4(s) && (s->type == SK_IP) && (s->flags & SKF_PKTINFO))
  {
    s->flags &= ~SKF_PKTINFO;
    s->flags |= SKF_HDRINCL;
    if (setsockopt(fd, SOL_IP, IP_HDRINCL, &y, sizeof(y)) < 0)
      ERR("IP_HDRINCL");
  }
#endif

  if (s->vrf && !s->iface)
  {
    /* Bind socket to associated VRF interface.
       This is Linux-specific, but so is SO_BINDTODEVICE. */
#ifdef SO_BINDTODEVICE
    struct ifreq ifr = {};
    strcpy(ifr.ifr_name, s->vrf->name);
    if (setsockopt(s->fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
      ERR("SO_BINDTODEVICE");
#endif
  }

  if (s->iface)
  {
#ifdef SO_BINDTODEVICE
    struct ifreq ifr = {};
    strcpy(ifr.ifr_name, s->iface->name);
    if (setsockopt(s->fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
      ERR("SO_BINDTODEVICE");
#endif

#ifdef CONFIG_UNIX_DONTROUTE
    if (setsockopt(s->fd, SOL_SOCKET, SO_DONTROUTE, &y, sizeof(y)) < 0)
      ERR("SO_DONTROUTE");
#endif
  }

  if (sk_is_ipv4(s))
  {
    if (s->flags & SKF_LADDR_RX)
      if (sk_request_cmsg4_pktinfo(s) < 0)
	return -1;

    if (s->flags & SKF_TTL_RX)
      if (sk_request_cmsg4_ttl(s) < 0)
	return -1;

    if ((s->type == SK_UDP) || (s->type == SK_IP))
      if (sk_disable_mtu_disc4(s) < 0)
	return -1;

    if (s->ttl >= 0)
      if (sk_set_ttl4(s, s->ttl) < 0)
	return -1;

    if (s->tos >= 0)
      if (sk_set_tos4(s, s->tos) < 0)
	return -1;
  }

  if (sk_is_ipv6(s))
  {
    if ((s->type == SK_TCP_PASSIVE) || (s->type == SK_TCP_ACTIVE) || (s->type == SK_UDP) ||
        (IS_SK_TLS(s->type)))
      if (setsockopt(fd, SOL_IPV6, IPV6_V6ONLY, &y, sizeof(y)) < 0)
	ERR("IPV6_V6ONLY");

    if (s->flags & SKF_LADDR_RX)
      if (sk_request_cmsg6_pktinfo(s) < 0)
	return -1;

    if (s->flags & SKF_TTL_RX)
      if (sk_request_cmsg6_ttl(s) < 0)
	return -1;

    if ((s->type == SK_UDP) || (s->type == SK_IP))
      if (sk_disable_mtu_disc6(s) < 0)
	return -1;

    if (s->ttl >= 0)
      if (sk_set_ttl6(s, s->ttl) < 0)
	return -1;

    if (s->tos >= 0)
      if (sk_set_tos6(s, s->tos) < 0)
	return -1;
  }

  /* Must be after sk_set_tos4() as setting ToS on Linux also mangles priority */
  if (s->priority >= 0)
    if (sk_set_priority(s, s->priority) < 0)
      return -1;

  return 0;
}

static void
sk_insert(sock *s)
{
  add_tail(&sock_list, &s->n);
}

static void
sk_tcp_connected(sock *s)
{
  sockaddr sa;
  int sa_len = sizeof(sa);

  if ((getsockname(s->fd, &sa.sa, &sa_len) < 0) ||
      (sockaddr_read(&sa, s->af, &s->saddr, &s->iface, &s->sport) < 0))
    log(L_WARN "SOCK: Cannot get local IP address for TCP>");

  s->type = SK_TCP;
  sk_alloc_bufs(s);
  s->tx_hook(s);
}

static int
tls_dummy_rx(sock *sk UNUSED, uint size UNUSED) {
    die("Internal error: %s function should NEVER be called", __FUNCTION__);
    return -1;
}

static void
tls_dummy_tx(sock *sk UNUSED) {
    die("Internal error: %s function should NEVER be called", __FUNCTION__);
}

static void
sk_unix_connected(sock *s) {
    s->type = SK_UNIX;
    sk_alloc_bufs(s);
    s->tx_hook(s);
}

int sk_open_active_unix(sock *sk, const char *control_path) {
    size_t check_size;

    if (sk->type != SK_UNIX_ACTIVE) {
        return -1;
    }

    check_size = strnlen(control_path, 109);
    if (check_size > 108) {
        return -1;
    }

    sk->host = mb_allocz(sk->pool, check_size + 1);
    strncpy((char *) sk->host, control_path, check_size); /* Yes, I know this is ugly cast */

    return sk_open(sk);
}

static void sk_tls_connected(sock *s) {
    sockaddr sa;
    int ret;
    int sa_len = sizeof(sa);

    if ((getsockname(s->fd, &sa.sa, &sa_len) < 0) ||
        (sockaddr_read(&sa, s->af, &s->saddr, &s->iface, &s->sport) < 0))
        log(L_WARN "SOCK: Cannot get local IP address for TLS>");

    s->type = SK_TLS_HANDSHAKE_IN_PROGRESS;
    sk_alloc_bufs(s);

    /* init ptls handshake */
    ret = ptls_handshake(s->tls->tls, &s->sendbuf, NULL, NULL, NULL);
    assert(ret == PTLS_ERROR_IN_PROGRESS);
    /* little trick to trigger write on io loop */
    s->tpos += 1; /* will be reset when handshake is completed */
    /* advance encrypted pos to trigger a socket write */
    s->encrypted_send_pos += s->sendbuf.off;

    /* dummy tls hooks to
     * take them into account
     * in poll syscall */
    s->active_rx_hook = s->rx_hook;
    s->active_tx_hook = s->tx_hook;
    s->passive_sock = NULL; // force NULL ptr

    s->rx_hook = tls_dummy_rx;
    s->tx_hook = tls_dummy_tx;

    //s->tx_hook(s);
}

#ifdef HAVE_LIBSSH
static void
sk_ssh_connected(sock *s)
{
  sk_alloc_bufs(s);
  s->type = SK_SSH;
  s->tx_hook(s);
}
#endif

static void tls_handshake_err_hook(sock *sk, int err) {
    rfree(sk);
}

static int
sk_passive_connected(sock *s, int type)
{
  sockaddr loc_sa, rem_sa;
  int loc_sa_len = sizeof(loc_sa);
  int rem_sa_len = sizeof(rem_sa);

  int fd = accept(s->fd, (((type == SK_TCP || type == SK_TLS_HANDSHAKE_IN_PROGRESS)) ? &rem_sa.sa : NULL), &rem_sa_len);
  if (fd < 0)
  {
    if ((errno != EINTR) && (errno != EAGAIN))
      s->err_hook(s, errno);
    return 0;
  }

  sock *t = sk_new(s->pool);
  t->type = type;
  t->data = s->data;
  t->af = s->af;
  t->fd = fd;
  t->ttl = s->ttl;
  t->tos = s->tos;
  t->vrf = s->vrf;
  t->rbsize = s->rbsize;
  t->tbsize = s->tbsize;

  if (s->type == SK_TLS_PASSIVE && s->tcp_auth_mode == AUTH_TCP_AO_TLS) {
      t->tcp_auth_mode = s->tcp_auth_mode;
      t->sndid = s->sndid;
      t->rcvid = s->rcvid;
  }

  if (type == SK_TCP || type  == SK_TLS_HANDSHAKE_IN_PROGRESS)
  {
    if ((getsockname(fd, &loc_sa.sa, &loc_sa_len) < 0) ||
	(sockaddr_read(&loc_sa, s->af, &t->saddr, &t->iface, &t->sport) < 0))
      log(L_WARN "SOCK: Cannot get local IP address for TCP<");

    if (sockaddr_read(&rem_sa, s->af, &t->daddr, &t->iface, &t->dport) < 0)
      log(L_WARN "SOCK: Cannot get remote IP address for TCP<");
  }

  if (sk_setup(t) < 0)
  {
    /* FIXME: Call err_hook instead ? */
    log(L_ERR "SOCK: Incoming connection: %s%#m", t->err);

    /* FIXME: handle it better in rfree() */
    close(t->fd);
    t->fd = -1;
    rfree(t);
    return 1;
  }

  sk_insert(t);
  sk_alloc_bufs(t);

  /* Do not call app until TLS handshake is not finished yet */
  if (type != SK_TLS_HANDSHAKE_IN_PROGRESS) {
      s->rx_hook(t, 0);
  } else {
      /* add dummy rx & tx to include this
       * socket in the poll syscall */

      /* add err hook to remove tcp socket if
       * something bad happens during TLS handshake */
      t->err_hook = tls_handshake_err_hook;

      t->tls = NULL; // still null
      t->tls_ctx = s->tls_ctx;
      t->passive_sock = s;

      /* FIXME ugly hack copy verifier context from server to get correct ctx on callback  */
      memcpy(t->tls_verif_obj, s->tls_verif_obj, sizeof(s->tls_verif_obj));
      if (tls_update_cb_ref(&t->tls_ctx, t->tls_verif_obj, sizeof(t->tls_verif_obj)) == -1) {
          printf("update error\n");
      }

      /* rx_hook will set corresponding data for the TLS state */
      s->rx_hook(t, 0);
      /* rx_hook should set the tls session
       * but on unexpected connect, the socket must be discarded */
      if (t->tls) {
          /* then, we replace dummy rx & tx to  */
          t->rx_hook = tls_dummy_rx;
          t->tx_hook = tls_dummy_tx;
          t->active_rx_hook = NULL; // force null because
          t->active_tx_hook = NULL; // non active socket
      }
  }
  return 1;
}

#ifdef HAVE_LIBSSH
/*
 * Return SSH_OK or SSH_AGAIN or SSH_ERROR
 */
static int
sk_ssh_connect(sock *s)
{
  s->fd = ssh_get_fd(s->ssh->session);

  /* Big fall thru automata */
  switch (s->ssh->state)
  {
  case SK_SSH_CONNECT:
  {
    switch (ssh_connect(s->ssh->session))
    {
    case SSH_AGAIN:
      /* A quick look into libSSH shows that ssh_get_fd() should return non-(-1)
       * after SSH_AGAIN is returned by ssh_connect(). This is however nowhere
       * documented but our code relies on that.
       */
      return SSH_AGAIN;

    case SSH_OK:
      break;

    default:
      return SSH_ERROR;
    }
  } /* fallthrough */

  case SK_SSH_SERVER_KNOWN:
  {
    s->ssh->state = SK_SSH_SERVER_KNOWN;

    if (s->ssh->server_hostkey_path)
    {
      int server_identity_is_ok = 1;

      /* Check server identity */
      switch (ssh_is_server_known(s->ssh->session))
      {
#define LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s,msg,args...) log(L_WARN "SSH Identity %s@%s:%u: " msg, (s)->ssh->username, (s)->host, (s)->dport, ## args);
      case SSH_SERVER_KNOWN_OK:
	/* The server is known and has not changed. */
	break;

      case SSH_SERVER_NOT_KNOWN:
	LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s, "The server is unknown, its public key was not found in the known host file %s", s->ssh->server_hostkey_path);
	break;

      case SSH_SERVER_KNOWN_CHANGED:
	LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s, "The server key has changed. Either you are under attack or the administrator changed the key.");
	server_identity_is_ok = 0;
	break;

      case SSH_SERVER_FILE_NOT_FOUND:
	LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s, "The known host file %s does not exist", s->ssh->server_hostkey_path);
	server_identity_is_ok = 0;
	break;

      case SSH_SERVER_ERROR:
	LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s, "Some error happened");
	server_identity_is_ok = 0;
	break;

      case SSH_SERVER_FOUND_OTHER:
	LOG_WARN_ABOUT_SSH_SERVER_VALIDATION(s, "The server gave use a key of a type while we had an other type recorded. " \
					     "It is a possible attack.");
	server_identity_is_ok = 0;
	break;
      }

      if (!server_identity_is_ok)
	return SSH_ERROR;
    }
  } /* fallthrough */

  case SK_SSH_USERAUTH:
  {
    s->ssh->state = SK_SSH_USERAUTH;
    switch (ssh_userauth_publickey_auto(s->ssh->session, NULL, NULL))
    {
    case SSH_AUTH_AGAIN:
      return SSH_AGAIN;

    case SSH_AUTH_SUCCESS:
      break;

    default:
      return SSH_ERROR;
    }
  } /* fallthrough */

  case SK_SSH_CHANNEL:
  {
    s->ssh->state = SK_SSH_CHANNEL;
    s->ssh->channel = ssh_channel_new(s->ssh->session);
    if (s->ssh->channel == NULL)
      return SSH_ERROR;
  } /* fallthrough */

  case SK_SSH_SESSION:
  {
    s->ssh->state = SK_SSH_SESSION;
    switch (ssh_channel_open_session(s->ssh->channel))
    {
    case SSH_AGAIN:
      return SSH_AGAIN;

    case SSH_OK:
      break;

    default:
      return SSH_ERROR;
    }
  } /* fallthrough */

  case SK_SSH_SUBSYSTEM:
  {
    s->ssh->state = SK_SSH_SUBSYSTEM;
    if (s->ssh->subsystem)
    {
      switch (ssh_channel_request_subsystem(s->ssh->channel, s->ssh->subsystem))
      {
      case SSH_AGAIN:
	return SSH_AGAIN;

      case SSH_OK:
	break;

      default:
	return SSH_ERROR;
      }
    }
  } /* fallthrough */

  case SK_SSH_ESTABLISHED:
    s->ssh->state = SK_SSH_ESTABLISHED;
  }

  return SSH_OK;
}

/*
 * Return file descriptor number if success
 * Return -1 if failed
 */
static int
sk_open_ssh(sock *s)
{
  if (!s->ssh)
    bug("sk_open() sock->ssh is not allocated");

  ssh_session sess = ssh_new();
  if (sess == NULL)
    ERR2("Cannot create a ssh session");
  s->ssh->session = sess;

  const int verbosity = SSH_LOG_NOLOG;
  ssh_options_set(sess, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
  ssh_options_set(sess, SSH_OPTIONS_HOST, s->host);
  ssh_options_set(sess, SSH_OPTIONS_PORT, &(s->dport));
  /* TODO: Add SSH_OPTIONS_BINDADDR */
  ssh_options_set(sess, SSH_OPTIONS_USER, s->ssh->username);

  if (s->ssh->server_hostkey_path)
    ssh_options_set(sess, SSH_OPTIONS_KNOWNHOSTS, s->ssh->server_hostkey_path);

  if (s->ssh->client_privkey_path)
    ssh_options_set(sess, SSH_OPTIONS_IDENTITY, s->ssh->client_privkey_path);

  ssh_set_blocking(sess, 0);

  switch (sk_ssh_connect(s))
  {
  case SSH_AGAIN:
    break;

  case SSH_OK:
    sk_ssh_connected(s);
    break;

  case SSH_ERROR:
    ERR2(ssh_get_error(sess));
    break;
  }

  return ssh_get_fd(sess);

 err:
  return -1;
}
#endif

/**
 * sk_open - open a socket
 * @s: socket
 *
 * This function takes a socket resource created by sk_new() and
 * initialized by the user and binds a corresponding network connection
 * to it.
 *
 * Result: 0 for success, -1 for an error.
 */
int
sk_open(sock *s)
{
  int af = AF_UNSPEC;
  int fd = -1;
  int do_bind = 0;
  int bind_port = 0;
  ip_addr bind_addr = IPA_NONE;
  sockaddr sa;

  if (s->type <= SK_IP || IS_SK_TLS(s->type))
  {
    /*
     * For TCP/IP sockets, Address family (IPv4 or IPv6) can be specified either
     * explicitly (SK_IPV4 or SK_IPV6) or implicitly (based on saddr, daddr).
     * But the specifications have to be consistent.
     */

    switch (s->subtype)
    {
    case 0:
      ASSERT(ipa_zero(s->saddr) || ipa_zero(s->daddr) ||
	     (ipa_is_ip4(s->saddr) == ipa_is_ip4(s->daddr)));
      af = (ipa_is_ip4(s->saddr) || ipa_is_ip4(s->daddr)) ? AF_INET : AF_INET6;
      break;

    case SK_IPV4:
      ASSERT(ipa_zero(s->saddr) || ipa_is_ip4(s->saddr));
      ASSERT(ipa_zero(s->daddr) || ipa_is_ip4(s->daddr));
      af = AF_INET;
      break;

    case SK_IPV6:
      ASSERT(ipa_zero(s->saddr) || !ipa_is_ip4(s->saddr));
      ASSERT(ipa_zero(s->daddr) || !ipa_is_ip4(s->daddr));
      af = AF_INET6;
      break;

    default:
      bug("Invalid subtype %d", s->subtype);
    }
  }

  switch (s->type)
  {
  case SK_TLS_ACTIVE:
  case SK_TCP_ACTIVE:
    s->ttx = "";			/* Force s->ttx != s->tpos */
    /* Fall thru */
  case SK_TLS_PASSIVE:
  case SK_TCP_PASSIVE:
    fd = socket(af, SOCK_STREAM, IPPROTO_TCP);
    bind_port = s->sport;
    bind_addr = s->saddr;
    do_bind = bind_port || ipa_nonzero(bind_addr);
    break;
  case SK_UNIX_ACTIVE:
    af = AF_UNIX;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    break;

#ifdef HAVE_LIBSSH
  case SK_SSH_ACTIVE:
    s->ttx = "";			/* Force s->ttx != s->tpos */
    fd = sk_open_ssh(s);
    break;
#endif

  case SK_UDP:
    fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
    bind_port = s->sport;
    bind_addr = (s->flags & SKF_BIND) ? s->saddr : IPA_NONE;
    do_bind = 1;
    break;

  case SK_IP:
    fd = socket(af, SOCK_RAW, s->dport);
    bind_port = 0;
    bind_addr = (s->flags & SKF_BIND) ? s->saddr : IPA_NONE;
    do_bind = ipa_nonzero(bind_addr);
    break;

  case SK_MAGIC:
    af = 0;
    fd = s->fd;
    break;

  default:
    bug("sk_open() called for invalid sock type %d", s->type);
  }

  if (fd < 0)
    ERR("socket");

  s->af = af;
  s->fd = fd;

  if (sk_setup(s) < 0)
    goto err;

  if (do_bind)
  {
    if (bind_port)
    {
      int y = 1;

      if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(y)) < 0)
	ERR2("SO_REUSEADDR");

#ifdef CONFIG_NO_IFACE_BIND
      /* Workaround missing ability to bind to an iface */
      if ((s->type == SK_UDP) && s->iface && ipa_zero(bind_addr))
      {
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &y, sizeof(y)) < 0)
	  ERR2("SO_REUSEPORT");
      }
#endif
    }
    else
      if (s->flags & SKF_HIGH_PORT)
	if (sk_set_high_port(s) < 0)
	  log(L_WARN "Socket error: %s%#m", s->err);

    if (s->flags & SKF_FREEBIND)
      if (sk_set_freebind(s) < 0)
        log(L_WARN "Socket error: %s%#m", s->err);

    sockaddr_fill(&sa, s->af, bind_addr, s->iface, bind_port);
    if (bind(fd, &sa.sa, SA_LEN(sa)) < 0)
      ERR2("bind");
  }

  if (s->password) {
      switch (s->tcp_auth_mode) {
          case AUTH_TCP_MD5:
              if (sk_set_md5_auth(s, s->saddr, s->daddr, -1, s->iface, s->password, 0) < 0)
                  goto err;
              break;
          case AUTH_TCP_AO:
          case AUTH_TCP_AO_TLS:
              if (sk_set_tcp_ao_auth(s, s->saddr, s->daddr, -1, s->iface, s->password,
                                     s->password_len, s->sndid, s->rcvid, 1) < 0)
                  goto err;
              log(L_INFO "TCP-AO enabled (%d): %s (sndid %d, rcvid %d)", s->type,
                  s->tcp_auth_mode == AUTH_TCP_AO ? "with provided password" : "draft-piraux-tcp-ao-tls mode",
                  s->sndid, s->rcvid);
              break;
          default:
              ERR2("TCP authentication mode not supported");
              break;
      }
  }

  switch (s->type)
  {
  case SK_TLS_ACTIVE:
  case SK_TCP_ACTIVE:
    sockaddr_fill(&sa, s->af, s->daddr, s->iface, s->dport);
    if (connect(fd, &sa.sa, SA_LEN(sa)) >= 0)
      if (s->type == SK_TCP_ACTIVE) sk_tcp_connected(s); else sk_tls_connected(s);
    else if (errno != EINTR && errno != EAGAIN && errno != EINPROGRESS &&
	     errno != ECONNREFUSED && errno != EHOSTUNREACH && errno != ENETUNREACH)
      ERR2("connect");
    break;

  case SK_TLS_PASSIVE:
  case SK_TCP_PASSIVE:
    if (listen(fd, 8) < 0)
      ERR2("listen");
    break;
  case SK_UNIX_ACTIVE: {
      /* little hack, put control_path to sk->host */
      struct sockaddr_un un_addr;
      memset(&un_addr, 0, sizeof(un_addr));
      un_addr.sun_family = AF_UNIX;
      strncpy(un_addr.sun_path, s->host, sizeof(un_addr.sun_path) - 1);
      if (connect(fd, (const struct sockaddr *) &un_addr, sizeof(un_addr)) >= 0) {
          sk_unix_connected(s);
      } else if (errno != EINTR && errno != EAGAIN && errno != EINPROGRESS &&
                 errno != ECONNREFUSED && errno != EHOSTUNREACH && errno != ENETUNREACH) {
          ERR2("UNIX Connect");
      }
      break;
  }
  case SK_SSH_ACTIVE:
  case SK_MAGIC:
    break;

  default:
    sk_alloc_bufs(s);
  }

  if (!(s->flags & SKF_THREAD))
    sk_insert(s);

  return 0;

err:
  close(fd);
  s->fd = -1;
  return -1;
}

int
sk_open_unix(sock *s, char *name)
{
  struct sockaddr_un sa;
  int fd;

  /* We are sloppy during error (leak fd and not set s->err), but we die anyway */

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    return -1;

  /* Path length checked in test_old_bird() but we may need unix sockets for other reasons in future */
  ASSERT_DIE(strlen(name) < sizeof(sa.sun_path));

  sa.sun_family = AF_UNIX;
  strcpy(sa.sun_path, name);

  if (bind(fd, (struct sockaddr *) &sa, SUN_LEN(&sa)) < 0)
    return -1;

  if (listen(fd, 8) < 0)
    return -1;

  s->fd = fd;
  sk_insert(s);
  return 0;
}


#define CMSG_RX_SPACE MAX(CMSG4_SPACE_PKTINFO+CMSG4_SPACE_TTL, \
			  CMSG6_SPACE_PKTINFO+CMSG6_SPACE_TTL)
#define CMSG_TX_SPACE MAX(CMSG4_SPACE_PKTINFO,CMSG6_SPACE_PKTINFO)

static void
sk_prepare_cmsgs(sock *s, struct msghdr *msg, void *cbuf, size_t cbuflen)
{
  if (sk_is_ipv4(s))
    sk_prepare_cmsgs4(s, msg, cbuf, cbuflen);
  else
    sk_prepare_cmsgs6(s, msg, cbuf, cbuflen);
}

static void
sk_process_cmsgs(sock *s, struct msghdr *msg)
{
  struct cmsghdr *cm;

  s->laddr = IPA_NONE;
  s->lifindex = 0;
  s->rcv_ttl = -1;

  for (cm = CMSG_FIRSTHDR(msg); cm != NULL; cm = CMSG_NXTHDR(msg, cm))
  {
    if ((cm->cmsg_level == SOL_IP) && sk_is_ipv4(s))
    {
      sk_process_cmsg4_pktinfo(s, cm);
      sk_process_cmsg4_ttl(s, cm);
    }

    if ((cm->cmsg_level == SOL_IPV6) && sk_is_ipv6(s))
    {
      sk_process_cmsg6_pktinfo(s, cm);
      sk_process_cmsg6_ttl(s, cm);
    }
  }
}


static inline int
sk_sendmsg(sock *s)
{
  struct iovec iov = {s->tbuf, s->tpos - s->tbuf};
  byte cmsg_buf[CMSG_TX_SPACE];
  sockaddr dst;
  int flags = 0;

  sockaddr_fill(&dst, s->af, s->daddr, s->iface, s->dport);

  struct msghdr msg = {
    .msg_name = &dst.sa,
    .msg_namelen = SA_LEN(dst),
    .msg_iov = &iov,
    .msg_iovlen = 1
  };

#ifdef CONFIG_DONTROUTE_UNICAST
  /* FreeBSD silently changes TTL to 1 when MSG_DONTROUTE is used, therefore we
     cannot use it for other cases (e.g. when TTL security is used). */
  if (ipa_is_ip4(s->daddr) && ip4_is_unicast(ipa_to_ip4(s->daddr)) && (s->ttl == 1))
    flags = MSG_DONTROUTE;
#endif

#ifdef CONFIG_USE_HDRINCL
  byte hdr[20];
  struct iovec iov2[2] = { {hdr, 20}, iov };

  if (s->flags & SKF_HDRINCL)
  {
    sk_prepare_ip_header(s, hdr, iov.iov_len);
    msg.msg_iov = iov2;
    msg.msg_iovlen = 2;
  }
#endif

  if (s->flags & SKF_PKTINFO)
    sk_prepare_cmsgs(s, &msg, cmsg_buf, sizeof(cmsg_buf));

  return sendmsg(s->fd, &msg, flags);
}

static inline int
sk_recvmsg(sock *s)
{
  struct iovec iov = {s->rbuf, s->rbsize};
  byte cmsg_buf[CMSG_RX_SPACE];
  sockaddr src;

  struct msghdr msg = {
    .msg_name = &src.sa,
    .msg_namelen = sizeof(src), // XXXX ??
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsg_buf,
    .msg_controllen = sizeof(cmsg_buf),
    .msg_flags = 0
  };

  int rv = recvmsg(s->fd, &msg, 0);
  if (rv < 0)
    return rv;

  //ifdef IPV4
  //  if (cf_type == SK_IP)
  //    rv = ipv4_skip_header(pbuf, rv);
  //endif

  sockaddr_read(&src, s->af, &s->faddr, NULL, &s->fport);
  sk_process_cmsgs(s, &msg);

  if (msg.msg_flags & MSG_TRUNC)
    s->flags |= SKF_TRUNCATED;
  else
    s->flags &= ~SKF_TRUNCATED;

  return rv;
}


static inline void reset_tx_buffer(sock *s) { s->ttx = s->tpos = s->tbuf; }


static int
sk_write_tls(sock *s) {
    int ret;
    int e;

    size_t max_data_send;
    size_t remaining_space;
    size_t data_to_send;
    size_t record_overhead;

    /* take buffer from app then encrypt */
    if (s->type == SK_TLS && s->tpos != s->ttx && !s->tls_drain) {

        max_data_send = s->tpos - s->ttx;
        remaining_space = s->encrypted_send_buf +
                s->encrypted_send_buf_len -
                s->encrypted_send_pos;
        record_overhead = ptls_get_record_overhead(s->tls->tls);

        if (remaining_space >= record_overhead) {
            remaining_space -= record_overhead;

            data_to_send = MIN(max_data_send, remaining_space);
            ret = ptls_send(s->tls->tls, &s->sendbuf, s->ttx,  data_to_send);
            if (ret != 0) {
                log(L_ERR "ptls_send to %N error (%d)", s->daddr, ret);
                s->err_hook(s, 0);
                return -1;
            }
            assert(s->sendbuf.is_allocated == 0);
            /* update encrypted_send_pos */
            s->encrypted_send_pos = s->encrypted_send_buf + s->sendbuf.off;
            /* we consumed user buffer, so update it */
            s->ttx += data_to_send; //s->tpos - s->ttx;
            assert(s->ttx <= s->tpos);
            if (s->ttx == s->tpos) {
                reset_tx_buffer(s);
                s->tls_drain = 1;
                /* trick for io_loop as encrypted buffer contains data */
                s->tpos += 1;
            }
        }
    }

    while (s->encrypted_send_off != s->encrypted_send_pos) {
        e = write(s->fd, s->encrypted_send_off, s->encrypted_send_pos - s->encrypted_send_off);
        if (e < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                /* reset_encrypt_tx_buffer; */
                s->encrypted_send_off = s->encrypted_send_pos = s->encrypted_send_buf;
                /* EPIPE is just a connection close notification during TX */
                s->err_hook(s, (errno != EPIPE) ? errno : 0);
                return -1;
            }
            return 0;
        }
        s->encrypted_send_off += e;
        assert(s->sendbuf.off >= e );
        s->sendbuf.off -= e;
    }
    /* reset ttx trick as no more data to send */
    if (s->encrypted_send_off == s->encrypted_send_pos) {
        if (s->type == SK_TLS_HANDSHAKE_IN_PROGRESS &&
            s->tpos != s->tbuf /* this happens when the server is receiving
                               * the first TLS data from the client */
            ) {
            s->tpos -= 1;
            assert(s->tpos == s->tbuf);
        }
        /* reset encrypted send buffer */
        s->encrypted_send_off = s->encrypted_send_buf;
        s->encrypted_send_pos = s->encrypted_send_buf;
        if (s->tls_drain) {
            /* no more pending data */
            s->tls_drain = 0;
            s->tpos -= 1;
            assert(s->tpos == s->tbuf);
            return 1; /* io is now ready to accept more data to write */
        }
    }

    if (s->type == SK_TLS_HANDSHAKE_IN_PROGRESS) {
        if (ptls_handshake_is_complete(s->tls->tls)) {
            //s->tpos -= 1;
            assert(s->tpos == s->tbuf);
            s->type = SK_TLS;
            /* now trigger app */
            if (s->rx_hook == tls_dummy_rx && s->passive_sock) {
                /* this socket was passive */
                s->tx_hook = s->passive_sock->tx_hook;
                s->rx_hook = s->passive_sock->rx_hook;
                s->passive_sock->rx_hook(s, 0);
            } else if (s->tx_hook == tls_dummy_tx && s->active_tx_hook) {
                /* this socket was active */
                s->tx_hook = s->active_tx_hook;
                s->rx_hook = s->active_rx_hook;
                s->tx_hook(s);
            } else {
                assert(0 && "Illegal intern state");
            }
            return 0;
        }
    }
    return 0;
}


static int
sk_maybe_write(sock *s)
{
  int e;

  switch (s->type)
  {
  case SK_TCP:
  case SK_MAGIC:
  case SK_UNIX:
    while (s->ttx != s->tpos)
    {
      e = write(s->fd, s->ttx, s->tpos - s->ttx);

      if (e < 0)
      {
	if (errno != EINTR && errno != EAGAIN)
	{
	  reset_tx_buffer(s);
	  /* EPIPE is just a connection close notification during TX */
	  s->err_hook(s, (errno != EPIPE) ? errno : 0);
	  return -1;
	}
	return 0;
      }
      s->ttx += e;
    }
    reset_tx_buffer(s);
    return 1;

#ifdef HAVE_LIBSSH
  case SK_SSH:
    while (s->ttx != s->tpos)
    {
      e = ssh_channel_write(s->ssh->channel, s->ttx, s->tpos - s->ttx);

      if (e < 0)
      {
	s->err = ssh_get_error(s->ssh->session);
	s->err_hook(s, ssh_get_error_code(s->ssh->session));

	reset_tx_buffer(s);
	/* EPIPE is just a connection close notification during TX */
	s->err_hook(s, (errno != EPIPE) ? errno : 0);
	return -1;
      }
      s->ttx += e;
    }
    reset_tx_buffer(s);
    return 1;
#endif
  case SK_TLS:
      return sk_write_tls(s);
  case SK_UDP:
  case SK_IP:
    {
      if (s->tbuf == s->tpos)
	return 1;

      e = sk_sendmsg(s);

      if (e < 0)
      {
	if (errno != EINTR && errno != EAGAIN)
	{
	  reset_tx_buffer(s);
	  s->err_hook(s, errno);
	  return -1;
	}

	if (!s->tx_hook)
	  reset_tx_buffer(s);
	return 0;
      }
      reset_tx_buffer(s);
      return 1;
    }

  default:
    bug("sk_maybe_write: unknown socket type %d", s->type);
  }
}

int
sk_rx_ready(sock *s)
{
  int rv;
  struct pollfd pfd = { .fd = s->fd };
  pfd.events |= POLLIN;

 redo:
  rv = poll(&pfd, 1, 0);

  if ((rv < 0) && (errno == EINTR || errno == EAGAIN))
    goto redo;

  return rv;
}

/**
 * sk_send - send data to a socket
 * @s: socket
 * @len: number of bytes to send
 *
 * This function sends @len bytes of data prepared in the
 * transmit buffer of the socket @s to the network connection.
 * If the packet can be sent immediately, it does so and returns
 * 1, else it queues the packet for later processing, returns 0
 * and calls the @tx_hook of the socket when the tranmission
 * takes place.
 */
int
sk_send(sock *s, unsigned len)
{
  s->ttx = s->tbuf;
  s->tpos = s->tbuf + len;
  return sk_maybe_write(s);
}

/**
 * sk_send_to - send data to a specific destination
 * @s: socket
 * @len: number of bytes to send
 * @addr: IP address to send the packet to
 * @port: port to send the packet to
 *
 * This is a sk_send() replacement for connection-less packet sockets
 * which allows destination of the packet to be chosen dynamically.
 * Raw IP sockets should use 0 for @port.
 */
int
sk_send_to(sock *s, unsigned len, ip_addr addr, unsigned port)
{
  s->daddr = addr;
  if (port)
    s->dport = port;

  s->ttx = s->tbuf;
  s->tpos = s->tbuf + len;
  return sk_maybe_write(s);
}

/*
int
sk_send_full(sock *s, unsigned len, struct iface *ifa,
	     ip_addr saddr, ip_addr daddr, unsigned dport)
{
  s->iface = ifa;
  s->saddr = saddr;
  s->daddr = daddr;
  s->dport = dport;
  s->ttx = s->tbuf;
  s->tpos = s->tbuf + len;
  return sk_maybe_write(s);
}
*/

static void
call_rx_hook(sock *s, int size)
{
  if (s->rx_hook(s, size))
  {
    /* We need to be careful since the socket could have been deleted by the hook */
    if (current_sock == s) {
      if (s->type == SK_TLS) {
        assert(s->rpos - s->rbuf == size); /* todo remove this */
        assert(s->recvbuf.off >= size); /* todo remove this also */
        s->recvbuf.off -= size;
        /* also, reset our off pointers */
      }
      s->rpos = s->rbuf;
    }
  }
}

static int
sk_read_tls(sock *s, int revents) {
    ssize_t c;
    int ret;
    byte *_rpos;
    size_t consumed;
    size_t input_off = 0;
    size_t total_to_read;
    int called_rx_hook = 0;

    c = read(s->fd, s->recv_txt_pos, s->recv_plain_txt + s->recv_plain_txt_len - s->recv_txt_pos);

    total_to_read = c + (s->recv_txt_pos - s->recv_plain_txt);

    if (c < 0) {
        if (errno != EINTR && errno != EAGAIN)
            s->err_hook(s, errno);
        else if (errno == EAGAIN && !(revents & POLLIN)) {
            log(L_ERR "Got EAGAIN from read when revents=%x (without POLLIN)", revents);
            s->err_hook(s, 0);
        }
    } else if (!c) {
        if (s->err_hook) s->err_hook(s, 0);
    } else {
        /* decrypt tls records */
        do {
            consumed = total_to_read - input_off;
            if (s->type == SK_TLS) {
                ret = ptls_receive(s->tls->tls, &s->recvbuf, s->recv_plain_txt + input_off, &consumed);
                if (ret != 0) {
                    //abort(); // should generate a core dump
                    die("ptls_receive error: %d", ret);
                }
                /* let's go, transmit the payload of one decrypted
                 * TLS record to the app at a time to avoid
                 * ptls_receive to malloc if s->rbuf is not large
                 * enough to receive the totality of data read from
                 * the socket s->fd. malloc is bad. */
                assert(!s->recvbuf.is_allocated); /* We really do not want ptls_receive to malloc */
                s->rpos = s->rbuf + s->recvbuf.off; // test
                _rpos = s->rpos;
                assert(s->rpos - s->rbuf == s->recvbuf.off);
                if (!s->rx_hook) return 0; // may the case on BGP collision resolution
                call_rx_hook(s, s->rpos - s->rbuf);
                called_rx_hook = 1;

                /* bgp might change the s->rpos pointer during packet processing............. */
                if (s->rpos != _rpos) {
                    assert(_rpos > s->rpos);
                    s->recvbuf.off -= _rpos - s->rpos;
                } // else {
                  //  /* rpos did not change. reset rpos = rbuf ???? */
                  // }
            } else if (s->type == SK_TLS_HANDSHAKE_IN_PROGRESS) {
                ret = ptls_handshake(s->tls->tls, &s->sendbuf, s->recv_plain_txt + input_off,
                                     &consumed, NULL);

                if (s->sendbuf.off == 0 && s->tpos != s->tbuf) {
                    /* reset ttx trick */
                    s->tpos -= 1;
                    assert(s->tpos == s->tbuf);
                } else if (s->tpos == s->tbuf) {
                    s->tpos += 1; /* trigger write for TLS handshake */
                    assert(s->tpos == s->tbuf + 1);
                }
                /* advance encrypted buffer offset */
                s->encrypted_send_pos += s->sendbuf.off;

                if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS) {
                    fprintf(stderr, "PTLS HANDSHAKE ERROR %d\n", ret);
                    if (s->err_hook) s->err_hook(s, 0);
                    return 0;
                }

                if (consumed == 0 && s->sendbuf.off == 0) {
                    /* since we do not send sendbuf directly,
                     * there is a chance that the loop will never end */
                    break;
                }
            }
            input_off += consumed;
        } while (ret == (s->type == SK_TLS_HANDSHAKE_IN_PROGRESS ? PTLS_ERROR_IN_PROGRESS : 0)
                 && input_off < total_to_read);

        /* shift non consumed data to the beginning of the buffer */
        if (input_off != total_to_read) {
            memmove(s->recv_plain_txt, s->recv_plain_txt + input_off, total_to_read - input_off);
            s->recv_txt_pos = s->recv_plain_txt + (total_to_read - input_off);
        } else {
            /* everything is consumed, so reset offset pointer */
            s->recv_txt_pos = s->recv_plain_txt;
        }

        if (s->type == SK_TLS) {
            return called_rx_hook;
        }
    }

    return 0;
}

#ifdef HAVE_LIBSSH
static int
sk_read_ssh(sock *s)
{
  ssh_channel rchans[2] = { s->ssh->channel, NULL };
  struct timeval timev = { 1, 0 };

  if (ssh_channel_select(rchans, NULL, NULL, &timev) == SSH_EINTR)
    return 1; /* Try again */

  if (ssh_channel_is_eof(s->ssh->channel) != 0)
  {
    /* The remote side is closing the connection */
    s->err_hook(s, 0);
    return 0;
  }

  if (rchans[0] == NULL)
    return 0; /* No data is available on the socket */

  const uint used_bytes = s->rpos - s->rbuf;
  const int read_bytes = ssh_channel_read_nonblocking(s->ssh->channel, s->rpos, s->rbsize - used_bytes, 0);
  if (read_bytes > 0)
  {
    /* Received data */
    s->rpos += read_bytes;
    call_rx_hook(s, used_bytes + read_bytes);
    return 1;
  }
  else if (read_bytes == 0)
  {
    if (ssh_channel_is_eof(s->ssh->channel) != 0)
    {
	/* The remote side is closing the connection */
	s->err_hook(s, 0);
    }
  }
  else
  {
    s->err = ssh_get_error(s->ssh->session);
    s->err_hook(s, ssh_get_error_code(s->ssh->session));
  }

  return 0; /* No data is available on the socket */
}
#endif

 /* sk_read() and sk_write() are called from BFD's event loop */

static inline int
sk_read_noflush(sock *s, int revents)
{
  switch (s->type)
  {
  case SK_TCP_PASSIVE:
    return sk_passive_connected(s, SK_TCP);
  case SK_TLS_PASSIVE:
    return sk_passive_connected(s, SK_TLS_HANDSHAKE_IN_PROGRESS);
  case SK_UNIX_PASSIVE:
    return sk_passive_connected(s, SK_UNIX);
  case SK_TLS_HANDSHAKE_IN_PROGRESS:
  case SK_TLS:
      return sk_read_tls(s, revents);
  case SK_TCP:
  case SK_UNIX:
    {
      int c = read(s->fd, s->rpos, s->rbuf + s->rbsize - s->rpos);

      if (c < 0)
      {
	if (errno != EINTR && errno != EAGAIN)
	  s->err_hook(s, errno);
	else if (errno == EAGAIN && !(revents & POLLIN))
	{
	  log(L_ERR "Got EAGAIN from read when revents=%x (without POLLIN)", revents);
	  s->err_hook(s, 0);
	}
      }
      else if (!c)
	s->err_hook(s, 0);
      else
      {
	s->rpos += c;
	call_rx_hook(s, s->rpos - s->rbuf);
	return 1;
      }
      return 0;
    }

#ifdef HAVE_LIBSSH
  case SK_SSH:
    return sk_read_ssh(s);
#endif
  case SK_MAGIC:
    return s->rx_hook(s, 0);

  default:
    {
      int e = sk_recvmsg(s);

      if (e < 0)
      {
	if (errno != EINTR && errno != EAGAIN)
	  s->err_hook(s, errno);
	return 0;
      }

      s->rpos = s->rbuf + e;
      s->rx_hook(s, e);
      return 1;
    }
  }
}

int
sk_read(sock *s, int revents)
{
  int e = sk_read_noflush(s, revents);
  tmp_flush();
  return e;
}

static inline int
sk_write_noflush(sock *s)
{
  switch (s->type)
  {
  case SK_TLS_ACTIVE:
  case SK_TCP_ACTIVE:
    {
      sockaddr sa;
      sockaddr_fill(&sa, s->af, s->daddr, s->iface, s->dport);

      if (connect(s->fd, &sa.sa, SA_LEN(sa)) >= 0 || errno == EISCONN) {
        if (s->type == SK_TCP_ACTIVE){
            sk_tcp_connected(s);
        } else {
            sk_tls_connected(s);
        }
      } else if (errno != EINTR && errno != EAGAIN && errno != EINPROGRESS){
          s->err_hook(s, errno);
      }
      return 0;
    }
  case SK_TLS:
  case SK_TLS_HANDSHAKE_IN_PROGRESS:
      if (sk_write_tls(s) > 0 && s->type == SK_TLS) {
          if (s->tx_hook) {
              s->tx_hook(s);
          }
          return 1;
      }
      return 0;
#ifdef HAVE_LIBSSH
  case SK_SSH_ACTIVE:
    {
      switch (sk_ssh_connect(s))
      {
	case SSH_OK:
	  sk_ssh_connected(s);
	  break;

	case SSH_AGAIN:
	  return 1;

	case SSH_ERROR:
	  s->err = ssh_get_error(s->ssh->session);
	  s->err_hook(s, ssh_get_error_code(s->ssh->session));
	  break;
      }
      return 0;
    }
#endif

  default:
    if (s->ttx != s->tpos && sk_maybe_write(s) > 0)
    {
      if (s->tx_hook)
	s->tx_hook(s);
      return 1;
    }
    return 0;
  }
}

int
sk_write(sock *s)
{
  int e = sk_write_noflush(s);
  tmp_flush();
  return e;
}

int sk_is_ipv4(sock *s)
{ return s->af == AF_INET; }

int sk_is_ipv6(sock *s)
{ return s->af == AF_INET6; }

void
sk_err(sock *s, int revents)
{
  int se = 0, sse = sizeof(se);
  if ((s->type != SK_MAGIC) && (revents & POLLERR))
    if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &se, &sse) < 0)
    {
      log(L_ERR "IO: Socket error: SO_ERROR: %m");
      se = 0;
    }

  s->err_hook(s, se);
  tmp_flush();
}

void
sk_dump_all(void)
{
  node *n;
  sock *s;

  debug("Open sockets:\n");
  WALK_LIST(n, sock_list)
  {
    s = SKIP_BACK(sock, n, n);
    debug("%p ", s);
    sk_dump(&s->r);
  }
  debug("\n");
}


/*
 *	Internal event log and watchdog
 */

#define EVENT_LOG_LENGTH 32

struct event_log_entry
{
  void *hook;
  void *data;
  btime timestamp;
  btime duration;
};

static struct event_log_entry event_log[EVENT_LOG_LENGTH];
static struct event_log_entry *event_open;
static int event_log_pos, event_log_num, watchdog_active;
static btime last_time;
static btime loop_time;

static void
io_update_time(void)
{
  struct timespec ts;
  int rv;

  /*
   * This is third time-tracking procedure (after update_times() above and
   * times_update() in BFD), dedicated to internal event log and latency
   * tracking. Hopefully, we consolidate these sometimes.
   */

  rv = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (rv < 0)
    die("clock_gettime: %m");

  last_time = ts.tv_sec S + ts.tv_nsec NS;

  if (event_open)
  {
    event_open->duration = last_time - event_open->timestamp;

    if (event_open->duration > config->latency_limit)
      log(L_WARN "Event 0x%p 0x%p took %u.%03u ms",
	  event_open->hook, event_open->data, (uint) (event_open->duration TO_MS), (uint) (event_open->duration % 1000));

    event_open = NULL;
  }
}

/**
 * io_log_event - mark approaching event into event log
 * @hook: event hook address
 * @data: event data address
 *
 * Store info (hook, data, timestamp) about the following internal event into
 * a circular event log (@event_log). When latency tracking is enabled, the log
 * entry is kept open (in @event_open) so the duration can be filled later.
 */
void
io_log_event(void *hook, void *data)
{
  if (config->latency_debug)
    io_update_time();

  struct event_log_entry *en = event_log + event_log_pos;

  en->hook = hook;
  en->data = data;
  en->timestamp = last_time;
  en->duration = 0;

  event_log_num++;
  event_log_pos++;
  event_log_pos %= EVENT_LOG_LENGTH;

  event_open = config->latency_debug ? en : NULL;
}

static inline void
io_close_event(void)
{
  if (event_open)
    io_update_time();
}

void
io_log_dump(void)
{
  int i;

  log(L_DEBUG "Event log:");
  for (i = 0; i < EVENT_LOG_LENGTH; i++)
  {
    struct event_log_entry *en = event_log + (event_log_pos + i) % EVENT_LOG_LENGTH;
    if (en->hook)
      log(L_DEBUG "  Event 0x%p 0x%p at %8d for %d ms", en->hook, en->data,
	  (int) ((last_time - en->timestamp) TO_MS), (int) (en->duration TO_MS));
  }
}

void
watchdog_sigalrm(int sig UNUSED)
{
  /* Update last_time and duration, but skip latency check */
  config->latency_limit = 0xffffffff;
  io_update_time();

  debug_safe("Watchdog timer timed out\n");

  /* We want core dump */
  abort();
}

static inline void
watchdog_start1(void)
{
  io_update_time();

  loop_time = last_time;
}

static inline void
watchdog_start(void)
{
  io_update_time();

  loop_time = last_time;
  event_log_num = 0;

  if (config->watchdog_timeout)
  {
    alarm(config->watchdog_timeout);
    watchdog_active = 1;
  }
}

static inline void
watchdog_stop(void)
{
  io_update_time();

  if (watchdog_active)
  {
    alarm(0);
    watchdog_active = 0;
  }

  btime duration = last_time - loop_time;
  if (duration > config->watchdog_warning)
    log(L_WARN "I/O loop cycle took %u.%03u ms for %d events",
	(uint) (duration TO_MS), (uint) (duration % 1000), event_log_num);
}


/*
 *	Main I/O Loop
 */

void
io_init(void)
{
  init_list(&sock_list);
  init_list(&global_event_list);
  init_list(&global_work_list);
  krt_io_init();
  // XXX init_times();
  // XXX update_times();
  boot_time = current_time();

  u64 now = (u64) current_real_time();
  srandom((uint) (now ^ (now >> 32)));
}

static int short_loops = 0;
#define SHORT_LOOP_MAX 10
#define WORK_EVENTS_MAX 10

void
io_loop(void)
{
  int poll_tout, timeout;
  int nfds, events, pout;
  timer *t;
  sock *s;
  node *n;
  int fdmax = 256;
  struct pollfd *pfd = xmalloc(fdmax * sizeof(struct pollfd));

  watchdog_start1();
  for(;;)
    {
      times_update(&main_timeloop);
      ev_run_list(&global_event_list);
      ev_run_list_limited(&global_work_list, WORK_EVENTS_MAX);
      timers_fire(&main_timeloop);
      io_close_event();

      events = !EMPTY_LIST(global_event_list) || !EMPTY_LIST(global_work_list);
      poll_tout = (events ? 0 : 3000); /* Time in milliseconds */
      if (t = timers_first(&main_timeloop))
      {
	times_update(&main_timeloop);
	timeout = (tm_remains(t) TO_MS) + 1;
	poll_tout = MIN(poll_tout, timeout);
      }

      nfds = 0;
      WALK_LIST(n, sock_list)
	{
	  pfd[nfds] = (struct pollfd) { .fd = -1 }; /* everything other set to 0 by this */
	  s = SKIP_BACK(sock, n, n);
	  if (s->rx_hook)
	    {
	      pfd[nfds].fd = s->fd;
	      pfd[nfds].events |= POLLIN;
	    }
	  if (s->tx_hook && s->ttx != s->tpos)
	    {
	      pfd[nfds].fd = s->fd;
	      pfd[nfds].events |= POLLOUT;
	    }
	  if (pfd[nfds].fd != -1)
	    {
	      s->index = nfds;
	      nfds++;
	    }
	  else
	    s->index = -1;

	  if (nfds >= fdmax)
	    {
	      fdmax *= 2;
	      pfd = xrealloc(pfd, fdmax * sizeof(struct pollfd));
	    }
	}

      /*
       * Yes, this is racy. But even if the signal comes before this test
       * and entering poll(), it gets caught on the next timer tick.
       */

      if (async_config_flag)
	{
	  io_log_event(async_config, NULL);
	  async_config();
	  async_config_flag = 0;
	  continue;
	}
      if (async_dump_flag)
	{
	  io_log_event(async_dump, NULL);
	  async_dump();
	  async_dump_flag = 0;
	  continue;
	}
      if (async_shutdown_flag)
	{
	  io_log_event(async_shutdown, NULL);
	  async_shutdown();
	  async_shutdown_flag = 0;
	  continue;
	}

      /* And finally enter poll() to find active sockets */
      watchdog_stop();
      pout = poll(pfd, nfds, poll_tout);
      watchdog_start();

      if (pout < 0)
	{
	  if (errno == EINTR || errno == EAGAIN)
	    continue;
	  die("poll: %m");
	}
      if (pout)
	{
	  times_update(&main_timeloop);

	  /* guaranteed to be non-empty */
	  current_sock = SKIP_BACK(sock, n, HEAD(sock_list));

	  while (current_sock)
	    {
	      sock *s = current_sock;
	      if (s->index == -1)
		{
		  current_sock = sk_next(s);
		  goto next;
		}

	      int e;
	      int steps;

	      steps = MAX_STEPS;
	      if (s->fast_rx && (pfd[s->index].revents & POLLIN) && s->rx_hook)
		do
		  {
		    steps--;
		    io_log_event(s->rx_hook, s->data);
		    e = sk_read(s, pfd[s->index].revents);
		    if (s != current_sock)
		      goto next;
		  }
		while (e && s->rx_hook && steps);

	      steps = MAX_STEPS;
	      if (pfd[s->index].revents & POLLOUT)
		do
		  {
		    steps--;
		    io_log_event(s->tx_hook, s->data);
		    e = sk_write(s);
		    if (s != current_sock)
		      goto next;
		  }
		while (e && steps);

	      current_sock = sk_next(s);
	    next: ;
	    }

	  short_loops++;
	  if (events && (short_loops < SHORT_LOOP_MAX))
	    continue;
	  short_loops = 0;

	  int count = 0;
	  current_sock = stored_sock;
	  if (current_sock == NULL)
	    current_sock = SKIP_BACK(sock, n, HEAD(sock_list));

	  while (current_sock && count < MAX_RX_STEPS)
	    {
	      sock *s = current_sock;
	      if (s->index == -1)
		{
		  current_sock = sk_next(s);
		  goto next2;
		}

	      if (!s->fast_rx && (pfd[s->index].revents & POLLIN) && s->rx_hook)
		{
		  count++;
		  io_log_event(s->rx_hook, s->data);
		  sk_read(s, pfd[s->index].revents);
		  if (s != current_sock)
		    goto next2;
		}

	      if (pfd[s->index].revents & (POLLHUP | POLLERR))
		{
		  sk_err(s, pfd[s->index].revents);
		  if (s != current_sock)
		    goto next2;
		}

	      current_sock = sk_next(s);
	    next2: ;
	    }


	  stored_sock = current_sock;
	}
    }
}

void
test_old_bird(char *path)
{
  int fd;
  struct sockaddr_un sa;

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    die("Cannot create socket: %m");
  if (strlen(path) >= sizeof(sa.sun_path))
    die("Socket path too long");
  bzero(&sa, sizeof(sa));
  sa.sun_family = AF_UNIX;
  strcpy(sa.sun_path, path);
  if (connect(fd, (struct sockaddr *) &sa, SUN_LEN(&sa)) == 0)
    die("I found another BIRD running.");
  close(fd);
}
