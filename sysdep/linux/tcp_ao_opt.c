
#include "nest/bird.h"
#include "lib/net.h"
#include "lib/socket.h"
#include "sysdep/unix/unix.h"

#include <string.h>
#include <linux/tcp.h>

static u8 tls_ao_initial__[] = (u8[]) {0x1c, 0xeb, 0xb1, 0xff};

char *tls_ao_initial = tls_ao_initial__;
size_t tls_ao_initial_len = sizeof(tls_ao_initial__);

int sk_del_tcp_ao_key(sock *s, ip_addr remote, int pxlen, struct iface *ifa,
                      int sndid, int rcvid);
int sk_add_tcp_ao_key(sock *s, ip_addr remote, int pxlen, struct iface *ifa,
                      const char *passwd, size_t passwd_len, u8 sndid, u8 rcvid);


static void sk_tls_ao_replace_ids(sock *sk) {
    if (sk->tcp_auth_mode != AUTH_TCP_AO_TLS) {
        return;
    }

    sk->prev_sndid = sk->sndid;
    sk->prev_rcvid = sk->rcvid;
    sk->sndid = ipa_hash(sk->saddr) % 255;
    sk->rcvid = ipa_hash(sk->daddr) % 255;
}

int sk_tcp_ao_rotate(sock *s, u8 curr_id, u8 next_id) {
    static char *err_msg;
    struct tcp_ao_info_opt opt;

    memset(&opt, 0, sizeof(opt));

    opt.set_current = 1;
    opt.set_rnext = 1;
    opt.current_key = curr_id;
    opt.rnext = next_id;

    if (setsockopt(s->fd, IPPROTO_TCP, TCP_AO_INFO, &opt, sizeof(opt)) == -1) {
        err_msg = strerror(errno);
        ERR_MSG(err_msg);
    }

    return 0;
}

int sk_tls_ao_replace_key(sock *sk) {
    char new_pwd[PTLS_MAX_DIGEST_SIZE];
    char debug_pwd[PTLS_MAX_DIGEST_SIZE * 3];
    size_t new_pwd_len;

    new_pwd_len = sizeof(new_pwd);

    if (sk->tcp_auth_mode != AUTH_TCP_AO_TLS) {
        return -1;
    }

    /* make sure this function is called only to switch from default secret to TLS derived one */
    assert((sk->sndid == 23 || sk->sndid == 10) &&
           (sk->rcvid == 23 || sk->rcvid == 10));
    sk_tls_ao_replace_ids(sk);

    /* if opportunistic TCP-AO change key here */
    if (tls_secret_exporter(sk->tls, new_pwd, &new_pwd_len) != 0) {
        log(L_ERR "Failed to retrieve TLS secret !");
        return -1;
    }

    for (size_t i = 0, j = 0; i < new_pwd_len; i++, j += 2) {
        snprintf(&debug_pwd[j], 3, "%02X", new_pwd[i]);
    }
    log(L_INFO "New MKT will be added: sndid: %d rcvid: %d, passwd: \"%s\"",
        sk->sndid, sk->rcvid, debug_pwd);

    /* 1. first add new key derived from tls session */
    if (sk_add_tcp_ao_key(sk, sk->daddr, -1, sk->iface,
                           new_pwd, new_pwd_len, sk->sndid, sk->rcvid) != 0) {
        log(L_ERR "TLS-AO new key add failed: %s", sk->err);
        return -1;
    }

    /* 2. rotate keys */
    if (sk_tcp_ao_rotate(sk, sk->sndid, sk->rcvid) != 0) {
        log(L_ERR "TCP-AO key rotation failed: %s", sk->err);
        return -1;
    }

    /* 3. then delete default key */
    if (sk_del_tcp_ao_key(sk, sk->daddr, -1, sk->iface, sk->prev_sndid, sk->prev_rcvid) != 0) {
        log(L_ERR "TLS-AO initial key removal failed: (sndid %d rcvid %d) %s",
            sk->prev_sndid, sk->prev_rcvid, sk->err);
        return -1;
    }


    return 0;
}

int sk_del_tcp_ao_key(sock *s, ip_addr remote, int pxlen, struct iface *ifa,
                      int sndid, int rcvid) {
    struct tcp_ao_del del;

    memset(&del, 0, sizeof(del));

    if (pxlen < 0) {
        pxlen = s->af == AF_INET ? 32 : 128;
    }

    sockaddr_fill((sockaddr *) &del.addr, s->af, remote, ifa, 0);
    del.prefix = pxlen;

    del.sndid = sndid;
    del.rcvid = rcvid;

    if (setsockopt(s->fd, IPPROTO_TCP, TCP_AO_DEL_KEY, &del, sizeof(del)) < 0) {
        if (errno == ENOPROTOOPT)
            ERR_MSG("Kernel does not support TCP AO signatures");
        else {
            ERR(strerror(errno));
        }
    }
    return 0;
}

int sk_add_tcp_ao_key(sock *s, ip_addr remote, int pxlen, struct iface *ifa,
                      const char *passwd, size_t passwd_len, u8 sndid, u8 rcvid) {
    static const char signature_alg[] = "cmac(aes128)";
    struct tcp_ao_info_opt opt;
    struct tcp_ao_add add;

    if (!IS_SK_TLS(s->type) && s->type != SK_TCP_PASSIVE && s->type != SK_TCP_ACTIVE) {
        ERR_MSG("Illegal socket type for TCP AO");
    }

    if (!passwd || passwd_len <= 0) {
        ERR_MSG("Password must be set and non zero");
    }

    memset(&add, 0, sizeof(add));
    memset(&opt, 0, sizeof(opt));

    memcpy(&add.alg_name, signature_alg, sizeof(signature_alg));
    /* allow only remote address if pxlen < 0 */
    if (pxlen < 0) {
        pxlen = s->af == AF_INET ? 32 : 128;
    }

    sockaddr_fill((sockaddr *) &add.addr, s->af, remote, ifa, 0);
    add.prefix = pxlen;


    if (passwd_len > TCP_AO_MAXKEYLEN) {
        ERR_MSG("The password for TCP AO Signature is too long");
    }
    add.keylen = passwd_len;
    memcpy(&add.key, passwd, passwd_len);

    add.sndid = sndid;
    add.rcvid = rcvid;

    if (setsockopt(s->fd, IPPROTO_TCP, TCP_AO_ADD_KEY, &add, sizeof(add)) < 0) {
        if (errno == ENOPROTOOPT)
            ERR_MSG("Kernel does not support TCP AO signatures");
        else
            ERR("TCP_AO_ADD_KEY");
    }

    /* setup tcp_ao required */
    opt.ao_required = 1;
    opt.accept_icmps = 0;

    if (setsockopt(s->fd, IPPROTO_TCP, TCP_AO_INFO, &opt, sizeof(opt)) < 0) {
        if (errno == ENOPROTOOPT)
            ERR_MSG("Kernel does not support TCP AO signatures");
        else
            ERR("TCP_AO_INFO");
    }

    return 0;
}

int
sk_set_tcp_ao_auth(sock *s, ip_addr local UNUSED, ip_addr remote, int pxlen, struct iface *ifa,
                   const char *passwd, size_t passwd_len, u8 sndid, u8 rcvid, int enable) {

    if (enable) {
        return sk_add_tcp_ao_key(s, remote, pxlen, ifa, passwd, passwd_len, sndid, rcvid);
    }

    return sk_del_tcp_ao_key(s, remote, pxlen, ifa, sndid, rcvid);
}