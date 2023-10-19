/*
 *	BIRD Socket Interface
 *
 *	(c) 1998--2004 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SOCKET_H_
#define _BIRD_SOCKET_H_

#include <errno.h>

#include "lib/resource.h"
#include "sysdep/unix/tls_helpers.h"

#ifdef HAVE_LIBSSH
#define LIBSSH_LEGACY_0_4
#include <libssh/libssh.h>
#endif

#include <picotls.h>

extern char *tls_ao_initial;
extern size_t tls_ao_initial_len;

#ifdef HAVE_LIBSSH
struct ssh_sock {
    const char *username;		/* (Required) SSH user name */
    const char *server_hostkey_path;	/* (Optional) Filepath to the SSH public key of remote side, can be knownhost file */
    const char *client_privkey_path;	/* (Optional) Filepath to the SSH private key of BIRD */
    const char *subsystem;		/* (Optional) Name of SSH subsytem */
    ssh_session session;		/* Internal */
    ssh_channel channel;		/* Internal */
    int state;				/* Internal */
#define SK_SSH_CONNECT		0	/* Start state */
#define SK_SSH_SERVER_KNOWN	1	/* Internal */
#define SK_SSH_USERAUTH		2	/* Internal */
#define SK_SSH_CHANNEL		3	/* Internal */
#define SK_SSH_SESSION		4	/* Internal */
#define SK_SSH_SUBSYSTEM 	5	/* Internal */
#define SK_SSH_ESTABLISHED	6	/* Final state */
};
#endif

typedef struct birdsock {
  resource r;
  pool *pool;				/* Pool where incoming connections should be allocated (for SK_xxx_PASSIVE) */
  int type;				/* Socket type */
  int subtype;				/* Socket subtype */
  void *data;				/* User data */
  ip_addr saddr, daddr;			/* IPA_NONE = unspecified */
  const char *host;			/* Alternative to daddr, NULL = unspecified */
  uint sport, dport;			/* 0 = unspecified (for IP: protocol type) */
  int tos;				/* TOS / traffic class, -1 = default */
  int priority;				/* Local socket priority, -1 = default */
  int ttl;				/* Time To Live, -1 = default */
  u32 flags;
  struct iface *iface;			/* Interface; specify this for broad/multicast sockets */
  struct iface *vrf;			/* Related VRF instance, NULL if global */

  byte *rbuf, *rpos;			/* NULL=allocate automatically */
  uint fast_rx;				/* RX has higher priority in event loop */
  uint rbsize;
  int (*rx_hook)(struct birdsock *, uint size); /* NULL=receiving turned off, returns 1 to clear rx buffer */

  byte *tbuf, *tpos;			/* NULL=allocate automatically */
  byte *ttx;				/* Internal */
  uint tbsize;
  void (*tx_hook)(struct birdsock *);

  void (*err_hook)(struct birdsock *, int); /* errno or zero if EOF */

  /* Information about received datagrams (UDP, RAW), valid in rx_hook */
  ip_addr faddr, laddr;			/* src (From) and dst (Local) address of the datagram */
  uint fport;				/* src port of the datagram */
  uint lifindex;			/* local interface that received the datagram */
  /* laddr and lifindex are valid only if SKF_LADDR_RX flag is set to request it */

  int af;				/* System-dependend adress family (e.g. AF_INET) */
  int fd;				/* System-dependent data */
  int index;				/* Index in poll buffer */
  int rcv_ttl;				/* TTL of last received datagram */
  node n;
  void *rbuf_alloc, *tbuf_alloc;
  const char *password;			/* Password for MD5 authentication */
  size_t password_len;
  int tcp_auth_mode;
  u8 sndid,rcvid; /* if tcp-ao, this is current sndid,recvd id of the MKT tuple */
  u8 prev_sndid,prev_rcvid; /* if tcp-ao, this is previous sndid,recvd id of the MKT tuple */
  const char *err;			/* Error message */
  struct ssh_sock *ssh;			/* Used in SK_SSH */

  /* for tls enabled socket*/
  ptls_context_t tls_ctx;
  ptls_ref_t *tls; /* tls connection context, must be released of sk_free */
  ptls_iovec_t certs[16]; /* max 16 certs */
  char tls_sign_obj[64]; /* todo remove magic number */
  char tls_verif_obj[64]; /* todo remove magic number */
  void *verif_x509_store; /* OpenSSL X509 verifier store, to be released on socket free */
  struct st_util_log_event_t log_evt;
  struct birdsock *passive_sock;
  int (*active_rx_hook)(struct birdsock *, uint size);
  void (*active_tx_hook)(struct birdsock *);


  byte *encrypted_send_buf, *encrypted_send_pos;
  byte *encrypted_send_off; /*  */
  uint encrypted_send_buf_len;
  ptls_buffer_t sendbuf; /* will contain data to be sent on the wire */
  byte *recv_plain_txt, *recv_txt_pos;
  uint recv_plain_txt_len;
  ptls_buffer_t recvbuf; /* contains decrypted data to send to the app */
  u8 tls_drain;

} sock;

sock *sock_new(pool *);			/* Allocate new socket */
#define sk_new(X) sock_new(X)		/* Wrapper to avoid name collision with OpenSSL */

int sk_open(sock *);			/* Open socket */
int sk_open_active_unix (sock *, const char *);
int sk_rx_ready(sock *s);
int sk_send(sock *, uint len);		/* Send data, <0=err, >0=ok, 0=sleep */
int sk_send_to(sock *, uint len, ip_addr to, uint port); /* sk_send to given destination */
void sk_reallocate(sock *);		/* Free and allocate tbuf & rbuf */
void sk_set_rbsize(sock *s, uint val);	/* Resize RX buffer */
void sk_set_tbsize(sock *s, uint val);	/* Resize TX buffer, keeping content */
void sk_set_tbuf(sock *s, void *tbuf);	/* Switch TX buffer, NULL-> return to internal */
void sk_dump_all(void);

int sk_is_ipv4(sock *s);		/* True if socket is IPv4 */
int sk_is_ipv6(sock *s);		/* True if socket is IPv6 */

static inline int sk_tx_buffer_empty(sock *sk)
{ return sk->tbuf == sk->tpos; }

int sk_setup_multicast(sock *s);	/* Prepare UDP or IP socket for multicasting */
int sk_join_group(sock *s, ip_addr maddr);	/* Join multicast group on sk iface */
int sk_leave_group(sock *s, ip_addr maddr);	/* Leave multicast group on sk iface */
int sk_setup_broadcast(sock *s);
int sk_set_ttl(sock *s, int ttl);	/* Set transmit TTL for given socket */
int sk_set_min_ttl(sock *s, int ttl);	/* Set minimal accepted TTL for given socket */
int sk_set_md5_auth(sock *s, ip_addr local, ip_addr remote, int pxlen, struct iface *ifa, const char *passwd, int setkey);
int sk_tls_ao_replace_key(sock *sk);
int sk_set_tcp_ao_auth(sock *s, ip_addr local UNUSED, ip_addr remote, int pxlen, struct iface *ifa, const char *passwd, size_t passwd_len, u8 sndid, u8 rcvid, int enable);
int sk_set_ipv6_checksum(sock *s, int offset);
int sk_set_icmp6_filter(sock *s, int p1, int p2);
void sk_log_error(sock *s, const char *p);
int sk_set_tls_cert(sock *s, const char *cert_location);
int sk_set_tls_private_key(sock *s, const char *pkey_location);
int sk_set_alpn(sock *s, const char *alpn, size_t alpn_len);
int sk_set_peer_sni(sock *s, const char *sni, size_t sni_len);
int sk_get_remote_cert(sock *s, char **const cert, size_t *len);
int sk_local_cert_to_pem(sock *s, char *pem_buf, size_t *pem_buf_len);
int sk_set_per_tls_session_state(sock *s, const char *sni, size_t sni_len,
                                 const char *alpn, size_t alpn_len, int server);
int sk_set_tls(sock *s, const char *cert_location, const char *pkey_location,
               const char *alpn, size_t alpn_len, const char *peer_sni,
               size_t peer_sni_len, const char *root_ca, const char *export_keys,
               const char *local_sni, size_t local_sni_name);

byte * sk_rx_buffer(sock *s, int *len);	/* Temporary */

extern int sk_priority_control;		/* Suggested priority for control traffic, should be sysdep define */


/* Socket flags */

#define SKF_V6ONLY	0x02	/* Use IPV6_V6ONLY socket option */
#define SKF_LADDR_RX	0x04	/* Report local address for RX packets */
#define SKF_TTL_RX	0x08	/* Report TTL / Hop Limit for RX packets */
#define SKF_BIND	0x10	/* Bind datagram socket to given source address */
#define SKF_HIGH_PORT	0x20	/* Choose port from high range if possible */
#define SKF_FREEBIND	0x40	/* Allow socket to bind to a nonlocal address */

#define SKF_THREAD	0x100	/* Socked used in thread, Do not add to main loop */
#define SKF_TRUNCATED	0x200	/* Received packet was truncated, set by IO layer */
#define SKF_HDRINCL	0x400	/* Used internally */
#define SKF_PKTINFO	0x800	/* Used internally */

/*
 *	Socket types		     SA SP DA DP IF  TTL SendTo	(?=may, -=must not, *=must)
 */

#define SK_TCP_PASSIVE	0	   /* ?  *  -  -  -  ?   -	*/
#define SK_TCP_ACTIVE	1          /* ?  ?  *  *  -  ?   -	*/
#define SK_TCP		2
#define SK_UDP		3          /* ?  ?  ?  ?  ?  ?   ?	*/
#define SK_IP		5          /* ?  -  ?  *  ?  ?   ?	*/
#define SK_MAGIC	7	   /* Internal use by sysdep code */
#define SK_UNIX_PASSIVE	8
#define SK_UNIX		9
#define SK_SSH_ACTIVE	10         /* -  -  *  *  -  ?   -	DA = host */
#define SK_SSH		11
#define SK_TLS_PASSIVE 12
#define SK_TLS_ACTIVE 13
#define SK_TLS 14
#define SK_TLS_HANDSHAKE_IN_PROGRESS 15
#define SK_UNIX_ACTIVE 16


#define IS_SK_TLS(t) ((t == SK_TLS_PASSIVE) || (t == SK_TLS_ACTIVE) || (t == SK_TLS) || (t == SK_TLS_HANDSHAKE_IN_PROGRESS))

/*
 *	Socket subtypes
 */

#define SK_IPV4		1
#define SK_IPV6		2

/*
 * For TCP/IP sockets, Address family (IPv4 or IPv6) can be specified either
 * explicitly (SK_IPV4 or SK_IPV6) or implicitly (based on saddr, daddr). But
 * these specifications must be consistent.
 *
 * For SK_UDP or SK_IP sockets setting DA/DP allows to use sk_send(), otherwise
 * sk_send_to() must be used.
 *
 * For SK_IP sockets setting DP specifies protocol number, which is used for
 * both receiving and sending.
 *
 * For multicast on SK_UDP or SK_IP sockets set IF and TTL, call
 * sk_setup_multicast() to enable multicast on that socket, and then use
 * sk_join_group() and sk_leave_group() to manage a set of received multicast
 * groups.
 *
 * For datagram (SK_UDP, SK_IP) sockets, there are two ways to handle source
 * address. The socket could be bound to it using bind() syscall, but that also
 * forbids the reception of multicast packets, or the address could be set on
 * per-packet basis using platform dependent options (but these are not
 * available in some corner cases). The first way is used when SKF_BIND is
 * specified, the second way is used otherwise.
 */


enum {
    AUTH_TCP_NO_AUTH = 0,
    AUTH_TCP_MD5,
    AUTH_TCP_AO,
    AUTH_TCP_AO_TLS,
};

#endif
