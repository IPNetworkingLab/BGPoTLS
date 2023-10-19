//
// Created by thomas on 12/10/23.
//

#include <openssl/pem.h>
#include "tls_helpers.h"

#include <picotls.h>
#include <picotls/openssl.h>
#include "nest/bird.h"
#include "lib/resource.h"

typedef void on_cert_received_cb_t(struct tls_ref *, char *, size_t len);

struct my_openssl_override_verify_certificate {
    struct st_ptls_openssl_override_verify_certificate_t override;
    struct tls_ref *tls_ref;
};


int create_x509_store(const char *root_ca, X509_STORE **my_store) {
    X509_STORE *store;
    X509 *cert;
    FILE *fp;
    int ret;

    ret = -1;
    store = X509_STORE_new();
    if (!store || !my_store) {
        goto err;
    }

    fp = fopen(root_ca, "rb");
    if (!fp) {
        goto err;
    }

    while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        if (!X509_STORE_add_cert(store, cert)) {
            goto err;
        }
    }

    *my_store = store;
    ret = 0;

    err:
    if (fp) fclose(fp);
    return ret;
}

/* taken from picotls */
static void log_event_cb(ptls_log_event_t *_self, ptls_t *tls, const char *type, const char *fmt, ...) {
    struct st_util_log_event_t *self = (struct st_util_log_event_t *) _self;
    char randomhex[PTLS_HELLO_RANDOM_SIZE * 2 + 1];
    va_list args;


    ptls_hexdump(randomhex, ptls_get_client_random(tls).base, PTLS_HELLO_RANDOM_SIZE);
    fprintf(self->fp, "%s %s ", type, randomhex);

    va_start(args, fmt);
    vfprintf(self->fp, fmt, args);
    va_end(args);

    fprintf(self->fp, "\n");
    fflush(self->fp);
}

int tls_init(ptls_context_t *ctx) {
    /* global context */
    memset(ctx, 0, sizeof(*ctx));
    ctx->random_bytes = ptls_openssl_random_bytes;
    ctx->key_exchanges = ptls_openssl_key_exchanges;
    ctx->cipher_suites = ptls_openssl_cipher_suites;
    ctx->get_time = &ptls_get_time;
    ctx->use_exporter = 1; /* needed to derive secret for TCP-AO */
    /* certificate verification context */
    /* both server and client should send their certificate */
    return 0;
}


static int cb_override_verifier(struct st_ptls_openssl_override_verify_certificate_t *self_, ptls_t *tls,
        int ret, int ossl_ret, X509 *cert, struct stack_st_X509 *chain) {
    unsigned int len = 0;
    unsigned char *data;

    struct my_openssl_override_verify_certificate *self = (struct my_openssl_override_verify_certificate *)self_;

    if (!cert) return ret; /* do NOT override ret value */
    if (!self->tls_ref) return ret;

    /* write cert in pem format */
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    len = BIO_get_mem_data(bio, &data);

    /* write data to mem */
    self->tls_ref->data.remote_cert = xmalloc(len);
    memcpy(self->tls_ref->data.remote_cert, data, len);
    self->tls_ref->data.remote_cert_len = len;

    BIO_free(bio);

    /* do NOT override return value of the default verifier */
    return ret;
}

/* FIXME: hack function to pass the correct cb "closure". Only used on passive socket */
int tls_update_cb_ref(ptls_context_t *ctx, char *verif_buf, size_t verif_buf_len) {
    struct my_openssl_override_verify_certificate *override;
    ptls_openssl_verify_certificate_t *verifier;


    if (sizeof(ptls_openssl_verify_certificate_t) +
        sizeof(struct my_openssl_override_verify_certificate) > verif_buf_len) {
        return -1;
    }

    verifier =  (ptls_openssl_verify_certificate_t *) verif_buf;
    override = (struct my_openssl_override_verify_certificate *) (verif_buf + sizeof(*verifier));

    ctx->verify_certificate = &verifier->super;

    verifier = (ptls_openssl_verify_certificate_t *) verif_buf;
    verifier->override_callback = &override->override;
    return 0;
}

int tls_set_root_ca(ptls_context_t *ctx, char *verif_buf, size_t verif_buf_len,
                    const char *root_ca, void **store_save_ptr) {
    ptls_openssl_verify_certificate_t *verifier;
    struct my_openssl_override_verify_certificate *override;
    X509_STORE *store;

    if (sizeof(ptls_openssl_verify_certificate_t) +
        sizeof(struct my_openssl_override_verify_certificate) > verif_buf_len) {
        return -1;
    }

    /* HACK:FIXME: ugly hack to pass custom callback to OpenSSL */
    verifier = (ptls_openssl_verify_certificate_t *) verif_buf;
    override = (struct my_openssl_override_verify_certificate *) (verif_buf + sizeof(*verifier));

    store = NULL;
    if (root_ca) {
        if (!store_save_ptr) return -1;
        if (create_x509_store(root_ca, &store) == -1) {
            return -1;
        }
        *store_save_ptr = store;
    }

    if (verif_buf) {
        memset(verifier, 0, sizeof(*verifier));
        memset(override, 0, sizeof(*override));
        if (ptls_openssl_init_verify_certificate(verifier, store) != 0) {
            return -1;
        }
        ctx->verify_certificate = &verifier->super;

        assert(!verifier->override_callback);
        // override->tls_ref will be set when tcp connection is established
        override->override.cb = cb_override_verifier;
        verifier->override_callback = &override->override;
    }

    return 0;
}

/* HACK: to be rewritten bad arithmetic pointers, and very specific function */
void tls_set_verifier_ctx(void *verif_buf, struct tls_ref *tls_ref) {
    struct my_openssl_override_verify_certificate *override;

    override = (struct my_openssl_override_verify_certificate *)
            (verif_buf + sizeof(ptls_openssl_verify_certificate_t));
    override->tls_ref = tls_ref;
}

int tls_get_remote_cert(ptls_ref_t *tls, char **cert, size_t *len) {
    if (!tls->data.remote_cert) return -1;

    *cert = tls->data.remote_cert;
    *len = tls->data.remote_cert_len;
    return 0;
}

void tls_free_verif_store(void *raw_store) {
    X509_STORE *store;
    store = (X509_STORE *) raw_store;

    X509_STORE_free(store);
}

int tls_set_certs(ptls_context_t *ctx, ptls_iovec_t *certs, int certs_max, const char *cert_location) {
    //static ptls_iovec_t certs[16];
    int count = 0;
    int i2d_len;
    X509 *cert;

    FILE *fp = fopen(cert_location, "rb");
    if (!fp) {
        return -1;
    }
    while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        if (count > certs_max) {
            return -1;
        }
        ptls_iovec_t *dst = certs + count++;
        if ((i2d_len = i2d_X509(cert, &dst->base)) < 0) {
            return -1;
        }
        dst->len = i2d_len;
    }
    fclose(fp);
    ctx->certificates.list = certs;
    ctx->certificates.count = count;
    return 0;
}

int tls_cert_to_pem(ptls_iovec_t *iovec_cert, char *pem_encoded_cert, size_t *len_pem) {
    unsigned char *data;
    uint8_t *base_cpy;
    unsigned int len;
    X509 *cert;

    /* d2i converts memory inplace ... */
    base_cpy = xmalloc(iovec_cert->len);
    memcpy(base_cpy, iovec_cert->base, iovec_cert->len);
    const uint8_t *p = base_cpy;

    cert = d2i_X509(NULL, &p, (long)iovec_cert->len);
    if (cert == NULL) {
        log(L_ERR "INVALID CERTIFICATE");
        xfree(base_cpy);
        return -1;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    len = BIO_get_mem_data(bio, &data);

    if (len > *len_pem) {
        *len_pem = len;
        BIO_free(bio);
        xfree(base_cpy);
        return -1;
    }

    *len_pem = len;
    memcpy(pem_encoded_cert, data, len);
    BIO_free(bio);
    xfree(base_cpy);
    return 0;
}

/* signer_buf is not from type ptls_openssl_sign_certificate_t
 * as picotls/openssl.h clashes with BIRD symbols */
int tls_set_pkey(ptls_context_t *ctx, const char *pem_pkey, char *signer_buf, size_t signer_buf_len) {
    FILE *fp;
    EVP_PKEY *pkey;
    ptls_openssl_sign_certificate_t *signer;

    if (signer_buf_len < sizeof(ptls_openssl_sign_certificate_t)) {
        return -1;
    }
    memset(signer_buf, 0, signer_buf_len);
    signer = (ptls_openssl_sign_certificate_t *) signer_buf;

    fp = fopen(pem_pkey, "rb");
    if (!fp) {
        return -1;
    }

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!pkey) {
        return -1;
    }
    fclose(fp);

    if (ptls_openssl_init_sign_certificate(signer, pkey) != 0) {
        return -1;
    }
    EVP_PKEY_free(pkey);
    ctx->sign_certificate = &signer->super;
    return 0;
}

/* taken from picotls */
int tls_setup_log_event(ptls_context_t *ctx, struct st_util_log_event_t *ls, const char *fn) {
    if ((ls->fp = fopen(fn, "at")) == NULL) {
        return -1;
    }
    ls->super.cb = log_event_cb;
    ctx->log_event = &ls->super;
    return 0;
}

int tls_secret_exporter(ptls_ref_t *ptls, char *out_secret, size_t *out_secret_len) {
    u8 secret[PTLS_MAX_DIGEST_SIZE];
    ptls_iovec_t ptls_iovec;
    ptls_cipher_suite_t *cipher;
    size_t digest_size;
    int ret;

    ptls_t *tls;
    tls = ptls->tls;

    if (!tls) {
        return -1;
    }

    cipher = ptls_get_cipher(tls);
    if (!cipher) {
        return -1;
    }

    digest_size = cipher->hash->digest_size;

    if (*out_secret_len < digest_size) {
        return -1;
    }

    memset(secret, 0, sizeof(secret));

    ptls_iovec = ptls_iovec_init(NULL, 0); // I guess this is additional data to hash with the secret key ? For now, nothing is added
    ret = ptls_export_secret(tls, secret, sizeof(secret), "TCP-AO-KEY",  ptls_iovec, 0);

    if (ret == 0) {
        memcpy(out_secret, secret, digest_size);
        *out_secret_len = digest_size;
    }

    return ret;
}

ptls_ref_t * tls_ref_new(ptls_context_t *tls_ctx, int is_server) {
    ptls_ref_t *tls;

    tls = xmalloc(sizeof(*tls));
    if (!tls) goto err;
    memset(tls, 0, sizeof(*tls));

    tls->tls = ptls_new(tls_ctx, is_server);
    if (!tls->tls) goto err;

    tls->reference = 1;
    return tls;

    err:
    if (tls) xfree(tls);
    return NULL;
}

void tls_ref_inc(ptls_ref_t *tls) {
    tls->reference += 1;
}

void tls_ref_dec(ptls_ref_t *tls) {
    assert(tls->reference > 0);
    tls->reference -= 1;
    if (!tls->reference) {
        if (tls->data.remote_cert) {
            xfree(tls->data.remote_cert);
            tls->data.remote_cert = NULL;
            tls->data.remote_cert_len = 0;
        }
        ptls_free(tls->tls);
        xfree(tls);
    }
}
