/**
 * OQS KEM parameters
 */

#include <stdio.h>
#include <openssl/x509.h>
#include "internal/asn1_int.h"
#include "internal/cryptlib.h"
#include "internal/evp_int.h"
#include <oqs/oqs.h>

typedef struct {
    OQS_KEM *k;
    uint8_t *pubkey;
    uint8_t *privkey;
    int security_bits;
    uint8_t *ciphertext;
} OQS_KEY;

/*
 * OQS key type
 */
typedef enum {
    KEY_TYPE_PUBLIC,
    KEY_TYPE_PRIVATE,
} oqs_key_type_t;


/*
 * Maps OpenSSL NIDs to OQS IDs
 */
static char* get_oqs_alg_name(int openssl_nid)
{
    switch (openssl_nid)
    {
        case NID_kyber512:
            return OQS_KEM_alg_kyber512;
        case NID_kyber768:
            return OQS_KEM_alg_kyber768;
        case NID_kyber1024:
            return OQS_KEM_alg_kyber1024;
        /* ADD_MORE_OQS_KEM_HERE */
        default:
            return NULL;
    }
}

/*
 * Returns the security level in bits for an OQS alg.
 */
static int get_oqs_security_bits(int openssl_nid)
{
    switch (openssl_nid) {
        case NID_kyber512:
            return 128;
        case NID_kyber768:
            return 192;
        case NID_kyber1024:
            return 256;
        default:
            return 0;
    }
}


static void oqs_pkey_ctx_free(OQS_KEY* key) {
  int privkey_len = 0;
  int ciphertext_len = 0;
  if (key->k) {
    privkey_len = key->k->length_secret_key;
    ciphertext_len = key->k->length_ciphertext;
    OQS_KEM_free(key->k);
  }
  if (key->privkey) {
    OPENSSL_secure_clear_free(key->privkey, privkey_len);
  }
  if (key->pubkey) {
    OPENSSL_free(key->pubkey);
  }
  if (key->ciphertext) {
    OPENSSL_secure_clear_free(key->ciphertext, ciphertext_len);
  }
  OPENSSL_free(key);
}

static int oqs_key_init(OQS_KEY **p_oqs_key, int nid, oqs_key_type_t keytype) {
    OQS_KEY *oqs_key = NULL;
    const char* oqs_alg_name = get_oqs_alg_name(nid);

    oqs_key = OPENSSL_zalloc(sizeof(*oqs_key));
    if (oqs_key == NULL) {
        DHerr(0, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    oqs_key->k = OQS_KEM_new(oqs_alg_name);
    if (oqs_key->k == NULL) {
        DHerr(0, ERR_R_FATAL);
        goto err;
    }
    oqs_key->pubkey = OPENSSL_malloc(oqs_key->k->length_public_key);
    if (oqs_key->pubkey == NULL) {
        DHerr(0, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (keytype == KEY_TYPE_PRIVATE) {
        oqs_key->privkey = OPENSSL_secure_malloc(oqs_key->k->length_secret_key);
        if (oqs_key->privkey == NULL) {
            DHerr(0, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
    oqs_key->security_bits = get_oqs_security_bits(nid);
    *p_oqs_key = oqs_key;
    return 1;

 err:
    oqs_pkey_ctx_free(oqs_key);
    return 0;
}

static int oqs_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) pkey->pkey.ptr;
    unsigned char *penc;

    if (!oqs_key || !oqs_key->k || !oqs_key->pubkey ) {
      DHerr(0, ERR_R_FATAL);
      return 0;
    }

    penc = OPENSSL_memdup(oqs_key->pubkey, oqs_key->k->length_public_key);
    if (penc == NULL) {
        DHerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey->ameth->pkey_id),
                                V_ASN1_UNDEF, NULL, penc, oqs_key->k->length_public_key)) {
        OPENSSL_free(penc);
        DHerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static int oqs_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen;
    X509_ALGOR *palg;
    OQS_KEY *oqs_key = NULL;
    int id = pkey->ameth->pkey_id;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey)) {
        return 0;
    }
    if (p == NULL) {
      /* pklen is checked below, after we instantiate the oqs_key to
         learn the expected len */
      DHerr(0, ERR_R_FATAL);
      return 0;
    }

    if (palg != NULL) {
      int ptype;

      /* Algorithm parameters must be absent */
      X509_ALGOR_get0(NULL, &ptype, NULL, palg);
      if (ptype != V_ASN1_UNDEF) {
        DHerr(0, ERR_R_FATAL);
        return 0;
      }
    }

    if (!oqs_key_init(&oqs_key, id, 0)) {
      DHerr(0, ERR_R_FATAL);
      return 0;
    }

    if (oqs_key->k && pklen != oqs_key->k->length_public_key) {
      DHerr(0, ERR_R_FATAL);
      oqs_pkey_ctx_free(oqs_key);
      return 0;
    }
    memcpy(oqs_key->pubkey, p, pklen);
    EVP_PKEY_assign(pkey, id, oqs_key);
    return 1;
}

static int oqs_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const OQS_KEY *akey = (OQS_KEY*) a->pkey.ptr;
    const OQS_KEY *bkey = (OQS_KEY*) b->pkey.ptr;

    if (akey == NULL || bkey == NULL) {
        return -2;
    }

    return CRYPTO_memcmp(akey->pubkey, bkey->pubkey, akey->k->length_public_key) == 0;
}

static int oqs_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    int plen;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;
    OQS_KEY *oqs_key = NULL;

    if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8)) {
        return 0;
    }

    oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
    if (oct == NULL) {
        p = NULL;
        plen = 0;
    } else {
        p = ASN1_STRING_get0_data(oct);
        plen = ASN1_STRING_length(oct);
    }

    /* oct contains first the private key, then the public key */
    if (palg != NULL) {
      int ptype;

      /* Algorithm parameters must be absent */
      X509_ALGOR_get0(NULL, &ptype, NULL, palg);
      if (ptype != V_ASN1_UNDEF) {
        DHerr(0, ERR_R_FATAL);
        return 0;
      }
    }

    if (!oqs_key_init(&oqs_key, pkey->ameth->pkey_id, 1)) {
      DHerr(0, ERR_R_FATAL);
      return 0;
    }

    if (plen != oqs_key->k->length_secret_key + oqs_key->k->length_public_key) {
      DHerr(0, ERR_R_FATAL);
      oqs_pkey_ctx_free(oqs_key);
      return 0;
    }

    memcpy(oqs_key->privkey, p, oqs_key->k->length_secret_key);
    memcpy(oqs_key->pubkey, p + oqs_key->k->length_secret_key, oqs_key->k->length_public_key);
    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, oqs_key);

    ASN1_OCTET_STRING_free(oct);
    return 1;
}

static int oqs_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) pkey->pkey.ptr;
    ASN1_OCTET_STRING oct;
    unsigned char *buf = NULL, *penc = NULL;
    int buflen = 0, penclen = 0;

    buflen = oqs_key->k->length_public_key + oqs_key->k->length_secret_key;


    buf = OPENSSL_secure_malloc(buflen);
    if (buf == NULL) {
        DHerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memcpy(buf, oqs_key->privkey, oqs_key->k->length_secret_key);
    memcpy(buf + oqs_key->k->length_secret_key, oqs_key->pubkey, oqs_key->k->length_public_key);
    oct.data = buf;
    oct.length = buflen;
    oct.flags = 0;

    penclen = i2d_ASN1_OCTET_STRING(&oct, &penc);
    if (penclen < 0) {
        DHerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    printf("name: %s\n", OBJ_nid2ln(pkey->ameth->pkey_id));
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

static int oqs_size(const EVP_PKEY *pkey) {
    const OQS_KEY *oqskey = (OQS_KEY*) pkey->pkey.ptr;
    return oqskey->k->length_shared_secret;
}

static int oqs_bits(const EVP_PKEY *pkey)
{
    const OQS_KEY *oqskey = (OQS_KEY*) pkey->pkey.ptr;
    return oqskey->k->length_public_key;
}

static int oqs_security_bits(const EVP_PKEY *pkey)
{
    return ((OQS_KEY*) pkey->pkey.ptr)->security_bits;
}

static void oqs_free(EVP_PKEY *pkey)
{
    oqs_pkey_ctx_free((OQS_KEY*) pkey->pkey.ptr);
}

/* "parameters" are always equal */
static int oqs_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    (void)a;
    (void)b;

    return 1;
}

static int oqs_key_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx, oqs_key_type_t keytype)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) pkey->pkey.ptr;
    const char *nm = OBJ_nid2ln(pkey->ameth->pkey_id);

    if (keytype == KEY_TYPE_PRIVATE) {
        if (oqs_key == NULL || oqs_key->privkey == NULL) {
            if (BIO_printf(bp, "%*s<INVALID PRIVATE KEY>\n", indent, "") <= 0) {
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
        if (ASN1_buf_print(bp, oqs_key->privkey, oqs_key->k->length_secret_key,
                           indent + 4) == 0) {
            return 0;
        }
    } else {
        if (oqs_key == NULL) {
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

    if (ASN1_buf_print(bp, oqs_key->pubkey, oqs_key->k->length_public_key,
                       indent + 4) == 0)
        return 0;

    (void)ctx;

    return 1;
}

static int oqs_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
  return oqs_key_print(bp, pkey, indent, ctx, KEY_TYPE_PRIVATE);
}

static int oqs_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx)
{
  return oqs_key_print(bp, pkey, indent, ctx, KEY_TYPE_PUBLIC);
}

static int pkey_oqs_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    OQS_KEY *oqs_key = NULL;
    int id = ctx->pmeth->pkey_id;

    if (!oqs_key_init(&oqs_key, id, 1)) {
        DHerr(0, ERR_R_FATAL);
        goto err;
    }

    if (OQS_KEM_keypair(oqs_key->k, oqs_key->pubkey, oqs_key->privkey) != OQS_SUCCESS) {
        DHerr(0, ERR_R_FATAL);
        goto err;
    }

    EVP_PKEY_assign(pkey, id, oqs_key);
    return 1;

 err:
    oqs_pkey_ctx_free(oqs_key);
    return 0;

}

static int pkey_oqs_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) {
    OQS_KEY *oqs_key = (OQS_KEY*) ctx->pkey->pkey.ptr;
    OQS_KEY *oqs_peer = (OQS_KEY*) ctx->peerkey->pkey.ptr;

    *keylen = oqs_size(ctx->pkey);
    if (key == NULL) {
        return 1;
    }
    if (oqs_peer->ciphertext) {
        if (OQS_KEM_decaps(oqs_key->k, key, oqs_peer->ciphertext, oqs_key->privkey) == OQS_SUCCESS) {
            return 1;
        }
    } else {
        oqs_peer->ciphertext = OPENSSL_malloc(*keylen);
        if (OQS_KEM_encaps(oqs_key->k, key, oqs_peer->ciphertext, oqs_peer->pubkey) == OQS_SUCCESS) {
            return 1;
        }
    }

    return 0;
}

static int pkey_oqs_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    switch (type) {
    case EVP_PKEY_CTRL_MD:
        /* Only NULL allowed as digest */
        if (p2 == NULL)
            return 1;
        DHerr(DH_F_PKEY_OQS_CTRL, ERR_R_FATAL);
        return 0;

    case EVP_PKEY_CTRL_DIGESTINIT:
        return 1;
    }
    return -2;
}

static int pkey_oqs_encapsulate(EVP_PKEY_CTX *ctx, unsigned char *key, unsigned char *ciphertext, size_t *keylen, size_t *ctlen) {
    OQS_KEY *oqs_key = (OQS_KEY*) ctx->pkey->pkey.ptr;
    OQS_KEY *oqs_peer;

    if (!ctx->pkey || !ctx->peerkey) {
        DHerr(DH_F_PKEY_OQS_ENCAPSULATE, DH_R_KEYS_NOT_SET);
        return 0;
    }
    oqs_peer = (OQS_KEY*) ctx->peerkey->pkey.ptr;

    *keylen = oqs_size(oqs_key);
    *ctlen = oqs_key->k->length_ciphertext;
    if (key == NULL && ciphertext == NULL) {
        return 1;
    }
    if (key == NULL || ciphertext == NULL) {
        DHerr(DH_F_PKEY_OQS_ENCAPSULATE, ERR_R_FATAL);
    }

    if (OQS_KEM_encaps(oqs_key->k, key, ciphertext, oqs_peer->pubkey) == OQS_SUCCESS) {
        return 1;
    }

    DHerr(DH_F_PKEY_OQS_ENCAPSULATE, ERR_R_FATAL);
    return 0;
}

static int pkey_oqs_decapsulate(EVP_PKEY_CTX *ctx, unsigned char *key, const unsigned char *ciphertext, size_t *keylen) {
    OQS_KEY *oqs_key = (OQS_KEY*) ctx->pkey->pkey.ptr;
    *keylen = oqs_size(oqs_key);

    if (key == NULL) {
        return 1;
    }

    if (OQS_KEM_decaps(oqs_key->k, key, ciphertext, oqs_key->privkey) == OQS_SUCCESS) {
        return 1;
    }

    DHerr(DH_F_PKEY_OQS_DECAPSULATE, ERR_R_FATAL);
    return 0;
}


#define DEFINE_OQS_EVP_PKEY_ASN1_METHOD(ALG, NID_ALG, SHORT_NAME, LONG_NAME) \
const EVP_PKEY_ASN1_METHOD ALG##_asn1_meth = { \
    NID_ALG,                                   \
    NID_ALG,                                   \
    0,                                         \
    SHORT_NAME,                                \
    LONG_NAME,                                 \
    oqs_pub_decode,                            \
    oqs_pub_encode,                            \
    oqs_pub_cmp,                               \
    oqs_pub_print,                             \
    oqs_priv_decode,                           \
    oqs_priv_encode,                           \
    oqs_priv_print,                            \
    oqs_size,                                  \
    oqs_bits,                                  \
    oqs_security_bits,                         \
    0, 0, 0, 0,                                \
    oqs_cmp_parameters,                        \
    0, 0,                                      \
    oqs_free,                                  \
    0, 0, 0,                                   \
    0,                                         \
    0,                                         \
    0,                                         \
    0, 0, 0, 0, 0,                             \
};

#define DEFINE_OQS_EVP_PKEY_METH(ALG, NID_ALG) \
const EVP_PKEY_METHOD ALG##_pkey_meth = {             \
    NID_ALG,    /* pkey_id */                         \
    0,          /* flags */                           \
    0,          /* init */                            \
    0,          /* copy */                            \
    0,          /* cleanup */                         \
    0,          /* paramgen_init */                   \
    0,          /* paramgen */                        \
    0,          /* keygen_init */                     \
    pkey_oqs_keygen, /* keygen */                     \
    0,          /* sign_init */                       \
    0,          /* sign */                            \
    0, 0,       /* verify_init, verify */             \
    0, 0,   /* verify_recover_init, verify_recover */ \
    0, 0,   /* signctx_init, signctx */               \
    0, 0,   /* verifyctx_init, verifyctx */           \
    0, 0,   /* encrypt_init, encrypt */               \
    0, 0,   /* decrypt_init, decrypt */               \
    0,      /* derive_init */                         \
    pkey_oqs_derive,  /* derive */                    \
    pkey_oqs_ctrl, 0,   /* ctrl, ctrl_str */          \
    0, 0,   /* digestsign, digestverify */            \
    0,      /* check */                               \
    0, 0,   /* public_check, param_check */           \
    0,      /* digest_custom */                       \
    0,      /* encapsulate_init */                    \
    pkey_oqs_encapsulate, /* encapsulate */           \
    0,      /* decapsulate_init */                    \
    pkey_oqs_decapsulate, /* decapsulate */           \
};



DEFINE_OQS_EVP_PKEY_ASN1_METHOD(kyber512, NID_kyber512, "kyber512", "OQS Kyber 512");
DEFINE_OQS_EVP_PKEY_METH(kyber512, NID_kyber512);
