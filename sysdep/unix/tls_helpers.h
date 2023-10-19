//
// Created by thomas on 12/10/23.
//

#ifndef BELBIRD_TLS_HELPERS_H
#define BELBIRD_TLS_HELPERS_H

#include <stdio.h>
#include <picotls.h>

/* for simplicity, we assume that
 * the max MTU of an ethernet frame is
 * 9000. Ideally, this should be fetched
 * from the kernel itself */
#define MAX_MTU 9000

struct tls_data {
    char *remote_cert;
    size_t remote_cert_len;
};

typedef struct tls_ref {
    ptls_t *tls;
    int reference;
    struct tls_data data;
} ptls_ref_t;

struct st_util_log_event_t {
    ptls_log_event_t super;
    FILE *fp;
};

int tls_init(ptls_context_t *ctx);

int tls_set_certs(ptls_context_t  *ctx, ptls_iovec_t *certs, int certs_max, const char *cert_location);

int tls_cert_to_pem(ptls_iovec_t *iovec_cert, char *pem_encoded_cert, size_t *len_pem);

int tls_set_pkey(ptls_context_t *ctx, const char *pem_pkey, char *signer_buf, size_t signer_buf_len);

int tls_set_root_ca(ptls_context_t *ctx, char *verif_buf, size_t verif_buf_len,
                    const char *root_ca, void **store_save_ptr);

int tls_get_remote_cert(ptls_ref_t *tls, char **cert, size_t *len);

void tls_set_verifier_ctx(void *verif_buf, struct tls_ref *tls_ref);

void tls_free_verif_store(void *raw_store);

int tls_setup_log_event(ptls_context_t *ctx, struct st_util_log_event_t *ls, const char *fn);

ptls_ref_t * tls_ref_new(ptls_context_t *tls_ctx, int is_server);

int tls_secret_exporter(ptls_ref_t *ptls, char *out_secret, size_t *out_secret_len);

void tls_ref_inc(ptls_ref_t *tls);

void tls_ref_dec(ptls_ref_t *tls);

/* HACK function: only use me if you know what you are doing */
int tls_update_cb_ref(ptls_context_t  *ctx, char *verif_buf, size_t verif_buf_len);

static inline int tls_set_alpn(ptls_t *tls, const char *alpn, size_t alpn_len) {
    return ptls_set_negotiated_protocol(tls, alpn, alpn_len) == 0 ? 0 : -1;
}

#endif //BELBIRD_TLS_HELPERS_H
