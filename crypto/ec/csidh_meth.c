/* Hacks CSIDH into OpenSSL */

#include <stdio.h>
#include <openssl/x509.h>
#include "internal/asn1_int.h"
#include "internal/cryptlib.h"
#include "internal/evp_int.h"
#include <csidh/csidh.h>
#include <assert.h>

typedef struct {
    csidh_private_key *priv;
    csidh_public_key *pub;
} CSIDH_KEY;

typedef enum {
    KEY_TYPE_PUBLIC,
    KEY_TYPE_PRIVATE,
} csidh_key_type_t;

static void csidh_free(CSIDH_KEY* key) {
    if (key->priv) {
        OPENSSL_secure_clear_free(key->priv, sizeof(csidh_private_key));
    }
    
    if (key->pub) {
        OPENSSL_free(key->pub);
    }

    OPENSSL_free(key);
}

static int csidh_key_init(CSIDH_KEY **p_csidh_key, int nid, csidh_key_type_t type) {
    CSIDH_KEY *csidh_key = NULL;

    csidh_key = OPENSSL_zalloc(sizeof(CSIDH_KEY));
    if (csidh_key == NULL) {
        DHerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    csidh_key->pub = OPENSSL_malloc(sizeof(csidh_public_key));
    if (csidh_key->pub == NULL) {
        DHerr(0, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (type == KEY_TYPE_PRIVATE) {
        csidh_key->priv = OPENSSL_secure_malloc(sizeof(csidh_private_key));
        if (csidh_key->priv == NULL) {
            DHerr(0, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
    *p_csidh_key = csidh_key;
    return 1;

err:
    csidh_free(csidh_key);
    return 0;

}

static int csidh_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey) {
    const CSIDH_KEY *csidh_key = (CSIDH_KEY*) pkey->pkey.ptr;
    unsigned char *penc;

    if (!csidh_key || !csidh_key->pub) {
        DHerr(0, ERR_R_FATAL);
        return 0;
    }
    penc = OPENSSL_memdup(csidh_key->pub, sizeof(csidh_public_key));
    if (penc == NULL) {
        DHerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if(!X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey->ameth->pkey_id),
                V_ASN1_UNDEF, NULL, penc, sizeof(csidh_public_key))) {
        OPENSSL_free(penc);
        DHerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static int csidh_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pkeylen;
    X509_ALGOR *palg;
    CSIDH_KEY *csidh_key = NULL;
    int id  = pkey->ameth->pkey_id;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pkeylen, &palg, pubkey)) {
        return 0;
    }
    if (p == NULL || pkeylen != sizeof(csidh_public_key)) {
        DHerr(0, ERR_R_FATAL);
        return 0;
    }

    if (!csidh_key_init(&csidh_key, id, KEY_TYPE_PUBLIC)) {
        DHerr(0, ERR_R_FATAL);
        return 0;
    }

    if (palg != NULL) {
        int ptype;

        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF) {
            DHerr(0, ERR_R_FATAL);
            return 0;
        }
    }

    memcpy(csidh_key->pub, p, sizeof(csidh_public_key));
    EVP_PKEY_assign(pkey, id, csidh_key);

    return 1;
}

static int csidh_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
    const CSIDH_KEY *akey = (CSIDH_KEY*) a->pkey.ptr;
    const CSIDH_KEY *bkey = (CSIDH_KEY*) b->pkey.ptr;

    if (akey == NULL || bkey == NULL) {
        return -2;
    }

    return CRYPTO_memcmp(akey->pub, bkey->pub, sizeof(csidh_public_key)) == 0;
}

static int csidh_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8) {
    const unsigned char *p;
    int plen;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;
    CSIDH_KEY *csidh_key = NULL;

    if(!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8)) {
        return 0;
    }
    oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
    if(oct == NULL) {
        p = NULL;
        plen = 0;
    } else {
        p = ASN1_STRING_get0_data(oct);
        plen = ASN1_STRING_length(oct);
    }

    /* oct contains private key followed by pubkey */
    if (palg != NULL) {
        int ptype;
        /* Algorithm parameters must be absent */
        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF) {
            DHerr(0, ERR_R_FATAL);
            return 0;
        }
    }

    if (plen != sizeof(csidh_private_key) + sizeof(csidh_public_key)) {
        DHerr(0, ERR_R_FATAL);
        ASN1_OCTET_STRING_free(oct);
        return 0;
    }

    if (!csidh_key_init(&csidh_key, NID_csidh512, KEY_TYPE_PRIVATE)) {
        DHerr(0, ERR_R_FATAL);
        return 0;
    }

    memcpy(csidh_key->priv, p, sizeof(csidh_private_key));
    memcpy(csidh_key->pub, p + sizeof(csidh_private_key), sizeof(csidh_public_key));
    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, csidh_key);

    ASN1_OCTET_STRING_free(oct);
    return 1;
}

static int csidh_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey) {
    const CSIDH_KEY *csidh_key = (CSIDH_KEY*) pkey->pkey.ptr;
    ASN1_OCTET_STRING oct;
    unsigned char *buf = NULL, *penc = NULL;
    int buflen = 0, penclen = 0;

    buflen = sizeof(csidh_private_key) + sizeof(csidh_public_key);
    buf = OPENSSL_secure_malloc(buflen);
    if (buf == NULL) {
        DHerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    memcpy(buf, csidh_key->priv, sizeof(csidh_private_key));
    memcpy(buf + sizeof(csidh_private_key), csidh_key->pub, sizeof(csidh_public_key));
    oct.data = buf;
    oct.length = buflen;
    oct.flags = 0;

    penclen = i2d_ASN1_OCTET_STRING(&oct, &penc);
    if (penclen < 0) {
        OPENSSL_secure_clear_free(buf, buflen);
        DHerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0,
                V_ASN1_UNDEF, NULL, penc, penclen)) {
        OPENSSL_secure_clear_free(buf, buflen);
        OPENSSL_clear_free(penc, penclen);
        DHerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    OPENSSL_secure_clear_free(buf, buflen);
    return 1;
}

static int csidh_size(const EVP_PKEY *pkey) {
    return sizeof(csidh_public_key);
}

static int csidh_bits(const EVP_PKEY *pkey) {
    return 512;
}

static int csidh_security_bits(const EVP_PKEY *pkey) {
    return 128;
}

static void csidh_free_pkey(EVP_PKEY *pkey) {
    csidh_free((CSIDH_KEY*) pkey->pkey.ptr);
}

static int csidh_cmp_params(const EVP_PKEY *a, const EVP_PKEY *b) {
    return 1;
}

static int csidh_key_print(BIO *bp, const EVP_PKEY *pkey, int indent,
        ASN1_PCTX *ctx, csidh_key_type_t keytype) {
    const CSIDH_KEY *csidh_key = (CSIDH_KEY*) pkey->pkey.ptr;
    const char *nm = OBJ_nid2ln(pkey->ameth->pkey_id);

    if (keytype == KEY_TYPE_PRIVATE) {
        if (csidh_key == NULL || csidh_key->priv == NULL) {
            if (BIO_printf(bp, "%*s<INVALID_PRIVATE_KEY>\n", indent, "") <= 0) {
                return 0;
            }
            return 1;
        }
        if (BIO_printf(bp, "%*s%s Private-Key:\n", indent, "", nm) <= 0) {
            return 0;
        }

        if (BIO_printf(bp, "%*spriv:\n", indent, "") <= 0) {
            return 0;
        }
        if (ASN1_buf_print(bp, (const uint8_t*)csidh_key->priv, sizeof(csidh_private_key),
                    indent + 4) == 0) {
            return 0;
        }
    } else {
        if (csidh_key == NULL) {
            if (BIO_printf(bp, "%*s<INVALID PUBLIC KEY>\n", indent, "") <= 0) {
                return 0;
            }
            return 1;
        }
        if (BIO_printf(bp, "%*s%s Public-Key:\n", indent, "", nm) <= 0) {
            return 0;
        }
    }
    if (BIO_printf(bp, "%*spub:\n", indent, "") <= 0) {
        return 0;
    }

    if (ASN1_buf_print(bp, (const uint8_t*)csidh_key->pub, sizeof(csidh_public_key), indent+4) == 0)
        return 0;
    return 1;
}

static int csidh_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx) {
    return csidh_key_print(bp, pkey, indent, ctx, KEY_TYPE_PRIVATE);
}

static int csidh_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx) {
    return csidh_key_print(bp, pkey, indent, ctx, KEY_TYPE_PUBLIC);
}

int pkey_csidh_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
    CSIDH_KEY *csidh_key = NULL;
    int id = ctx->pmeth->pkey_id;
    if (!csidh_key_init(&csidh_key, id, 1)) {
        DHerr(0, ERR_R_FATAL);
        return 0;
    }

    csidh_generate(csidh_key->priv);
    if (csidh_derive(csidh_key->pub, &csidh_base, csidh_key->priv)) {
        DHerr(0, ERR_R_FATAL);
        csidh_free(csidh_key);
        return 0;
    }

    EVP_PKEY_assign(pkey, id, csidh_key);
    return 1;
}

int pkey_csidh_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
    return 1;
}

int pkey_csidh_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) {
    CSIDH_KEY *csidh_key = NULL;
    CSIDH_KEY *csidh_peer = NULL;
    if (!ctx->pkey || !ctx->peerkey) {
        DHerr(0, DH_R_KEYS_NOT_SET);
        return 0;
    }
    csidh_key = (CSIDH_KEY*) ctx->pkey->pkey.ptr;
    csidh_peer = (CSIDH_KEY*) ctx->peerkey->pkey.ptr;

    *keylen = sizeof(csidh_public_key);

    if (key == NULL) {
        return 1;
    }

    csidh_derive((csidh_public_key*) key, csidh_peer->pub, csidh_key->priv);
    return 1;
}

/* define those structs set in dh_ameth.c and dh_pmeth.c */
/* Figure out where they are included. */

const EVP_PKEY_ASN1_METHOD csidh512_asn1_meth = {
    NID_csidh512,
    NID_csidh512,
    0,
    "CSIDH512",
    "CSIDH 512 bits",
    csidh_pub_decode,
    csidh_pub_encode,
    csidh_pub_cmp,
    csidh_pub_print,
    csidh_priv_decode,
    csidh_priv_encode,
    csidh_priv_print,
    csidh_size,
    csidh_bits,
    csidh_security_bits,
    0, 0, 0, 0,
    csidh_cmp_params,
    0, 0,
    csidh_free_pkey,
};

const EVP_PKEY_METHOD csidh512_pkey_meth = {
    NID_csidh512,    /* pkey_id */
    0,          /* flags */
    0,          /* init */
    0,          /* copy */
    0,          /* cleanup */
    0,          /* paramgen_init */
    0,          /* paramgen */
    0,          /* keygen_init */
    pkey_csidh_keygen, /* keygen */
    0,          /* sign_init */
    0,          /* sign */
    0, 0,       /* verify_init, verify */
    0, 0,   /* verify_recover_init, verify_recover */
    0, 0,   /* signctx_init, signctx */
    0, 0,   /* verifyctx_init, verifyctx */
    0, 0,   /* encrypt_init, encrypt */
    0, 0,   /* decrypt_init, decrypt */
    0, pkey_csidh_derive,   /* derive_init, derive */
    pkey_csidh_ctrl,   /* ctrl, ctrl_str */
};

