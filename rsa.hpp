#pragma("once")
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include<limits.h>
#include <assert.h>
#include <unistd.h>

typedef struct rsa_meth_st RSA_METHOD;
typedef struct rsa_st RSA;
typedef struct engine_st ENGINE;
typedef struct bignum_st BIGNUM;
typedef struct X509_algor_st X509_ALGOR;
typedef struct asn1_object_st ASN1_OBJECT;
typedef struct st_engine_table ENGINE_TABLE;
typedef struct st_engine_pile ENGINE_PILE;
typedef struct lhash_st LHASH;
#  define BN_ULONG        unsigned long long
# define STACK_OF(type) struct stack_st_##type
# define LHASH_OF(type) struct lhash_st_##type


typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef struct asn1_string_st ASN1_STRING;
typedef int ASN1_BOOLEAN;
typedef int ASN1_NULL;
typedef struct ASN1_VALUE_st ASN1_VALUE;
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
typedef int CRYPTO_REF_COUNT;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct lhash_node_st OPENSSL_LH_NODE;

typedef enum bnrand_flag_e {
    NORMAL, TESTING, PRIVATE
} BNRAND_FLAG;

struct lhash_node_st {
    void *data;
    struct lhash_node_st *next;
    unsigned long hash;
};

typedef int (*OPENSSL_LH_COMPFUNC) (const void *, const void *);
typedef unsigned long (*OPENSSL_LH_HASHFUNC) (const void *);

struct lhash_st {
    OPENSSL_LH_NODE **b;
    OPENSSL_LH_COMPFUNC comp;
    OPENSSL_LH_HASHFUNC hash;
    unsigned int num_nodes;
    unsigned int num_alloc_nodes;
    unsigned int p;
    unsigned int pmax;
    unsigned long up_load;      /* load times 256 */
    unsigned long down_load;    /* load times 256 */
    unsigned long num_items;
    unsigned long num_expands;
    unsigned long num_expand_reallocs;
    unsigned long num_contracts;
    unsigned long num_contract_reallocs;
    volatile unsigned long num_hash_calls;
    volatile unsigned long num_comp_calls;
    unsigned long num_insert;
    unsigned long num_replace;
    unsigned long num_delete;
    unsigned long num_no_delete;
    volatile unsigned long num_retrieve;
    volatile unsigned long num_retrieve_miss;
    volatile unsigned long num_hash_comps;
    int error;
};

# define BIO_CTRL_RESET          1/* opt - rewind/zero etc */
# define BIO_CTRL_EOF            2/* opt - are we at the eof */
# define BIO_CTRL_INFO           3/* opt - extra tit-bits */
# define BIO_CTRL_SET            4/* man - set the 'IO' type */
# define BIO_CTRL_GET            5/* man - get the 'IO' type */
# define BIO_CTRL_PUSH           6/* opt - internal, used to signify change */
# define BIO_CTRL_POP            7/* opt - internal, used to signify change */
# define BIO_CTRL_GET_CLOSE      8/* man - set the 'close' on free */
# define BIO_CTRL_SET_CLOSE      9/* man - set the 'close' on free */
# define BIO_CTRL_PENDING        10/* opt - is their more data buffered */
# define BIO_CTRL_FLUSH          11/* opt - 'flush' buffered output */
# define BIO_CTRL_DUP            12/* man - extra stuff for 'duped' BIO */
# define BIO_CTRL_WPENDING       13/* opt - number of bytes still to write */
# define BIO_CTRL_SET_CALLBACK   14/* opt - set callback function */
# define BIO_CTRL_GET_CALLBACK   15/* opt - set callback function */

# define BIO_CTRL_PEEK           29/* BIO_f_buffer special */
# define BIO_CTRL_SET_FILENAME   30/* BIO_s_file special */

/* dgram BIO stuff */
# define BIO_CTRL_DGRAM_CONNECT       31/* BIO dgram special */
# define BIO_CTRL_DGRAM_SET_CONNECTED 32/* allow for an externally connected
                                         * socket to be passed in */
# define BIO_CTRL_DGRAM_SET_RECV_TIMEOUT 33/* setsockopt, essentially */
# define BIO_CTRL_DGRAM_GET_RECV_TIMEOUT 34/* getsockopt, essentially */
# define BIO_CTRL_DGRAM_SET_SEND_TIMEOUT 35/* setsockopt, essentially */
# define BIO_CTRL_DGRAM_GET_SEND_TIMEOUT 36/* getsockopt, essentially */

# define BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP 37/* flag whether the last */
# define BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP 38/* I/O operation tiemd out */

/* #ifdef IP_MTU_DISCOVER */
# define BIO_CTRL_DGRAM_MTU_DISCOVER       39/* set DF bit on egress packets */
/* #endif */

# define BIO_CTRL_DGRAM_QUERY_MTU          40/* as kernel for current MTU */
# define BIO_CTRL_DGRAM_GET_FALLBACK_MTU   47
# define BIO_CTRL_DGRAM_GET_MTU            41/* get cached value for MTU */
# define BIO_CTRL_DGRAM_SET_MTU            42/* set cached value for MTU.
                                              * want to use this if asking
                                              * the kernel fails */

# define BIO_CTRL_DGRAM_MTU_EXCEEDED       43/* check whether the MTU was
                                              * exceed in the previous write
                                              * operation */

# define BIO_CTRL_DGRAM_GET_PEER           46
# define BIO_CTRL_DGRAM_SET_PEER           44/* Destination for the data */

# define BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT   45/* Next DTLS handshake timeout
                                              * to adjust socket timeouts */
# define BIO_CTRL_DGRAM_SET_DONT_FRAG      48

# define BIO_CTRL_DGRAM_GET_MTU_OVERHEAD   49

/* Deliberately outside of OPENSSL_NO_SCTP - used in bss_dgram.c */
#  define BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE    50
# ifndef OPENSSL_NO_SCTP
/* SCTP stuff */
#  define BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY                51
#  define BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY               52
#  define BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD               53
#  define BIO_CTRL_DGRAM_SCTP_GET_SNDINFO         60
#  define BIO_CTRL_DGRAM_SCTP_SET_SNDINFO         61
#  define BIO_CTRL_DGRAM_SCTP_GET_RCVINFO         62
#  define BIO_CTRL_DGRAM_SCTP_SET_RCVINFO         63
#  define BIO_CTRL_DGRAM_SCTP_GET_PRINFO                  64
#  define BIO_CTRL_DGRAM_SCTP_SET_PRINFO                  65
#  define BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN               70
# endif

# define BIO_CTRL_DGRAM_SET_PEEK_MODE      71
# define BIO_FLAGS_NONCLEAR_RST  0x400
# define BIO_C_SET_BUF_MEM                       114
# define BIO_C_GET_BUF_MEM_PTR                   115
# define BIO_C_SET_BUF_MEM_EOF_RETURN            130

struct asn1_string_st {
    int length;
    int type;
    unsigned char *data;
    long flags;
};

/* The type of the items in the table */
struct st_engine_pile {
    /* The 'nid' of this algorithm/mode */
    int nid;
    /* ENGINEs that implement this algorithm/mode. */
    STACK_OF(ENGINE) *sk;
    /* The default ENGINE to perform this algorithm/mode. */
    ENGINE *funct;
    /*
     * Zero if 'sk' is newer than the cached 'funct', non-zero otherwise
     */
    int uptodate;
};

/* The type exposed in eng_int.h */
struct st_engine_table {
    LHASH piles;
};

typedef struct asn1_type_st {
    int type;
    union {
        char *ptr;
        ASN1_BOOLEAN boolean;
        ASN1_STRING *asn1_string;
        ASN1_OBJECT *object;
        ASN1_INTEGER *integer;
        ASN1_ENUMERATED *enumerated;
        ASN1_BIT_STRING *bit_string;
        ASN1_OCTET_STRING *octet_string;
        ASN1_PRINTABLESTRING *printablestring;
        ASN1_T61STRING *t61string;
        ASN1_IA5STRING *ia5string;
        ASN1_GENERALSTRING *generalstring;
        ASN1_BMPSTRING *bmpstring;
        ASN1_UNIVERSALSTRING *universalstring;
        ASN1_UTCTIME *utctime;
        ASN1_GENERALIZEDTIME *generalizedtime;
        ASN1_VISIBLESTRING *visiblestring;
        ASN1_UTF8STRING *utf8string;
        /*
         * set and sequence are left complete and still contain the set or
         * sequence bytes
         */
        ASN1_STRING *set;
        ASN1_STRING *sequence;
        ASN1_VALUE *asn1_value;
    } value;
} ASN1_TYPE;



struct asn1_object_st {
    const char *sn, *ln;
    int nid;
    int length;
    const unsigned char *data;  /* data remains const after init */
    int flags;                  /* Should we free this one */
};


struct X509_algor_st {
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameter;
} /* X509_ALGOR */ ;


typedef struct rsa_pss_params_st {
    X509_ALGOR *hashAlgorithm;
    X509_ALGOR *maskGenAlgorithm;
    ASN1_INTEGER *saltLength;
    ASN1_INTEGER *trailerField;
    /* Decoded hash algorithm from maskGenAlgorithm */
    X509_ALGOR *maskHash;
} RSA_PSS_PARAMS;

struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
                                 * chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
};


/* Used for montgomery multiplication */
struct bn_mont_ctx_st {
    int ri;                     /* number of bits in R */
    BIGNUM RR;                  /* used to convert to montgomery form,
                                   possibly zero-padded */
    BIGNUM N;                   /* The modulus */
    BIGNUM Ni;                  /* R*(1/R mod N) - N*Ni = 1 (Ni is only
                                 * stored for bignum algorithm) */
    BN_ULONG n0[2];             /* least significant word(s) of Ni; (type
                                 * changed with 0.9.9, was "BN_ULONG n0;"
                                 * before) */
    int flags;
};

struct rsa_meth_st {
    char *name;
    int (*rsa_priv_dec) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding);
    /* called at new */
    int (*init) (RSA *rsa);
    int flags;
    char *app_data;
};

# define RSA_FLAG_FIPS_METHOD                    0x0400
# define RSA_FLAG_NON_FIPS_ALLOW                 0x0400
#define BN_CTX_POOL_SIZE        16


/* A bundle of bignums that can be linked with other bundles */
typedef struct bignum_pool_item {
    /* The bignum values */
    BIGNUM vals[BN_CTX_POOL_SIZE];
    /* Linked-list admin */
    struct bignum_pool_item *prev, *next;
} BN_POOL_ITEM;
/* A linked-list of bignums grouped in bundles */
typedef struct bignum_pool {
    /* Linked-list admin */
    BN_POOL_ITEM *head, *current, *tail;
    /* Stack depth and allocation size */
    unsigned used, size;
} BN_POOL;
typedef struct bignum_ctx BN_CTX;

/* A wrapper to manage the "stack frames" */
typedef struct bignum_ctx_stack {
    /* Array of indexes into the bignum stack */
    unsigned int *indexes;
    /* Number of stack frames, and the size of the allocated array */
    unsigned int depth, size;
} BN_STACK;


/* The opaque BN_CTX type */
struct bignum_ctx {
    /* The bignum bundles */
    BN_POOL pool;
    /* The "stack frames", if you will */
    BN_STACK stack;
    /* The number of bignums currently assigned */
    unsigned int used;
    /* Depth of stack overflow */
    int err_stack;
    /* Block "gets" until an "end" (compatibility behaviour) */
    int too_many;
    /* Flags. */
    int flags;
};

struct bn_blinding_st {
    BIGNUM *A;
    BIGNUM *Ai;
    BIGNUM *e;
    BIGNUM *mod;                /* just a reference */
    int counter;
    unsigned long flags;
    BN_MONT_CTX *m_ctx;
    int (*bn_mod_exp) (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
};

# define RSA_FLAG_CACHE_PUBLIC           0x0002
# define RSA_FLAG_CACHE_PRIVATE          0x0004
typedef struct rand_meth_st RAND_METHOD;
struct rand_meth_st {
    int (*seed) (const void *buf, int num);
    int (*bytes) (unsigned char *buf, int num);
    void (*cleanup) (void);
    int (*add) (const void *buf, int num, double randomness);
    int (*pseudorand) (unsigned char *buf, int num);
    int (*status) (void);
};


struct engine_st {
    const char *id;
    const char *name;
    const RSA_METHOD *rsa_meth;
    const RAND_METHOD *rand_meth;
    struct engine_st *prev;
    struct engine_st *next;
};


struct crypto_ex_data_st {
    STACK_OF(void) *sk;
};

typedef unsigned int CRYPTO_THREAD_ID;
typedef struct bn_blinding_st BN_BLINDING;
typedef void CRYPTO_RWLOCK;

struct rsa_st {
    /*
     * The first parameter is used to pickup errors where this is passed
     * instead of an EVP_PKEY, it is set to 0
     */
    int pad;
    int32_t version;
    const RSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    /* be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;
    CRYPTO_REF_COUNT references;
    int flags;
    /* Used to cache montgomery values */
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;
    /*
     * all BIGNUM values are actually in the following data, if it is not
     * NULL
     */
    char *bignum_data;
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
};


void *CRYPTO_malloc(size_t num)
{
    void *ret = NULL;
    if (num == 0)
        return NULL;

    ret = malloc(num);
    return ret;
}

void CRYPTO_free(void *str)
{
    free(str);
    str = NULL;
}

void *CRYPTO_zalloc(size_t num)
{
    void *ret = CRYPTO_malloc(num);
    if (ret != NULL)
        memset(ret, 0, num);
    return ret;
}

static void BN_POOL_init(BN_POOL *p)
{
    p->head = p->current = p->tail = NULL;
    p->used = p->size = 0;
}

static void BN_STACK_init(BN_STACK *st)
{
    st->indexes = NULL;
    st->depth = st->size = 0;
}

BN_CTX *BN_CTX_new(void)
{
    BN_CTX *ret;

    if ((ret = (BN_CTX *)CRYPTO_zalloc(sizeof(*ret))) == NULL) {
        eosio_assert(false,"malloc error");
        return NULL;
    }
    /* Initialise the structure */
    BN_POOL_init(&ret->pool);
    BN_STACK_init(&ret->stack);
    return ret;
}

#define BN_CTX_START_FRAMES     32
static int BN_STACK_push(BN_STACK *st, unsigned int idx)
{
    if (st->depth == st->size) {
        /* Need to expand */
        unsigned int newsize =
                st->size ? (st->size * 3 / 2) : BN_CTX_START_FRAMES;
        unsigned int *newitems;

        if ((newitems = (unsigned int *)CRYPTO_malloc(sizeof(*newitems) * newsize)) == NULL) {
            eosio_assert(false,"openssl_malloc error");
            return 0;
        }
        if (st->depth)
            memcpy(newitems, st->indexes, sizeof(*newitems) * st->depth);
        CRYPTO_free(st->indexes);
        st->indexes = newitems;
        st->size = newsize;
    }
    st->indexes[(st->depth)++] = idx;
    return 1;
}


void BN_CTX_start(BN_CTX *ctx)
{
    if (ctx->err_stack || ctx->too_many)
        ctx->err_stack++;
    else if (!BN_STACK_push(&ctx->stack, ctx->used)) {
        ctx->err_stack++;
    }
}

void bn_init(BIGNUM *a)
{
    static BIGNUM nilbn;
    *a = nilbn;
}

# define BN_FLG_SECURE           0x08
void BN_set_flags(BIGNUM *b, int n)
{
    b->flags |= n;
}

static BIGNUM *BN_POOL_get(BN_POOL *p, int flag)
{
    BIGNUM *bn;
    unsigned int loop;

    /* Full; allocate a new pool item and link it in. */
    if (p->used == p->size) {
        BN_POOL_ITEM *item;

        if ((item = (BN_POOL_ITEM *)CRYPTO_malloc(sizeof(*item))) == NULL) {
            eosio_assert(false,"malloc error");
            return NULL;
        }
        for (loop = 0, bn = item->vals; loop++ < BN_CTX_POOL_SIZE; bn++) {
            bn_init(bn);
            if ((flag & BN_FLG_SECURE) != 0)
                BN_set_flags(bn, BN_FLG_SECURE);
        }
        item->prev = p->tail;
        item->next = NULL;

        if (p->head == NULL)
            p->head = p->current = p->tail = item;
        else {
            p->tail->next = item;
            p->tail = item;
            p->current = item;
        }
        p->size += BN_CTX_POOL_SIZE;
        p->used++;
        /* Return the first bignum from the new pool */
        return item->vals;
    }

    if (!p->used)
        p->current = p->head;
    else if ((p->used % BN_CTX_POOL_SIZE) == 0)
        p->current = p->current->next;
    return p->current->vals + ((p->used++) % BN_CTX_POOL_SIZE);
}

#  define BN_FLG_FIXED_TOP 0
#  define BN_zero(a)      (BN_set_word((a),0))
#  define BN_BYTES        8
# define BN_BITS2       (BN_BYTES * 8)
# define BN_FLG_STATIC_DATA      0x02

int BN_get_flags(const BIGNUM *b, int n)
{
    return b->flags & n;
}

void OPENSSL_cleanse(void *ptr, size_t len)
{
    memset(ptr, 0, len);
}


static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words)
{
    BN_ULONG *a = NULL;

    if (words > (INT_MAX / (4 * BN_BITS2))) {
        eosio_assert(false, "BN_F_BN_EXPAND_INTERNAL, BN_R_BIGNUM_TOO_LONG");
        return NULL;
    }
    if (BN_get_flags(b, BN_FLG_STATIC_DATA)) {
        eosio_assert(false, "BN_F_BN_EXPAND_INTERNAL, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA");
        return NULL;
    }
    if (BN_get_flags(b, BN_FLG_SECURE))
        a = (BN_ULONG *)CRYPTO_zalloc(words * sizeof(*a));
    else
        a = (BN_ULONG *)CRYPTO_zalloc(words * sizeof(*a));
    if (a == NULL) {
        eosio_assert(false, "BN_F_BN_EXPAND_INTERNAL, ERR_R_MALLOC_FAILURE");
        return NULL;
    }

    assert(b->top <= words);
    if (b->top > 0)
        memcpy(a, b->d, sizeof(*a) * b->top);

    return a;
}

static void bn_free_d(BIGNUM *a)
{
    if (BN_get_flags(a, BN_FLG_SECURE))
        CRYPTO_free(a->d);
    else
        CRYPTO_free(a->d);
}

BIGNUM *bn_expand2(BIGNUM *b, int words)
{
    if (words > b->dmax) {
        BN_ULONG *a = bn_expand_internal(b, words);
        if (!a)
            return NULL;
        if (b->d) {
            OPENSSL_cleanse(b->d, b->dmax * sizeof(b->d[0]));
            bn_free_d(b);
        }
        b->d = a;
        b->dmax = words;
    }

    return b;
}

static BIGNUM *bn_expand(BIGNUM *a, int bits)
{
    if (bits > (INT_MAX - BN_BITS2 + 1))
    return NULL;

    if (((bits+BN_BITS2-1)/BN_BITS2) <= (a)->dmax)
    return a;

    return bn_expand2((a),(bits+BN_BITS2-1)/BN_BITS2);
}

int BN_set_word(BIGNUM *a, BN_ULONG w)
{
    if (bn_expand(a, (int)sizeof(BN_ULONG) * 8) == NULL)
        return 0;
    a->neg = 0;
    a->d[0] = w;
    a->top = (w ? 1 : 0);
    a->flags &= ~BN_FLG_FIXED_TOP;
    return 1;
}

BIGNUM *BN_CTX_get(BN_CTX *ctx)
{
    BIGNUM *ret;
    if (ctx->err_stack || ctx->too_many)
        return NULL;
    if ((ret = BN_POOL_get(&ctx->pool, ctx->flags)) == NULL) {
        ctx->too_many = 1;
        eosio_assert(false,"get error");
        return NULL;
    }
    /* OK, make sure the returned bignum is "zero" */
    BN_zero(ret);
    ctx->used++;
    return ret;
}

int BN_is_zero(const BIGNUM *a)
{
    return a->top == 0;
}

#  define BN_MASK2 0xffffffffffffffffL
int BN_num_bits_word(BN_ULONG l)
{
    BN_ULONG x, mask;
    int bits = (l != 0);

    x = l >> 32;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 32 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 16;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 16 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 8;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 8 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 4;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 4 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 2;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 2 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 1;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 1 & mask;

    return bits;
}

int BN_num_bits(const BIGNUM *a)
{
    int i = a->top - 1;
    if (BN_is_zero(a))
        return 0;

    return ((i * BN_BITS2) + BN_num_bits_word(a->d[i]));
}


# define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)
int RSA_size(const RSA *r)
{
    return BN_num_bytes(r->n);
}

# define BN_FLG_MALLOCED         0x01
BIGNUM *BN_new(void)
{
    BIGNUM *ret;
    if ((ret = (BIGNUM *)CRYPTO_zalloc(sizeof(*ret))) == NULL) {
        eosio_assert(false,"BN_F_BN_NEW, ERR_R_MALLOC_FAILURE");
        return NULL;
    }

    ret->flags = BN_FLG_MALLOCED;
    return ret;
}

BIGNUM *bn_wexpand(BIGNUM *a, int words)
{
    return (words <= a->dmax) ? a : bn_expand2(a, words);
}

void BN_free(BIGNUM *a)
{
    if (a == NULL)
        return;
    if (!BN_get_flags(a, BN_FLG_STATIC_DATA))
        bn_free_d(a);
    if (a->flags & BN_FLG_MALLOCED)
        CRYPTO_free(a);
}

void bn_correct_top(BIGNUM *a)
{
    BN_ULONG *ftl;
    int tmp_top = a->top;

    if (tmp_top > 0) {
        for (ftl = &(a->d[tmp_top]); tmp_top > 0; tmp_top--) {
            ftl--;
            if (*ftl != 0)
                break;
        }
        a->top = tmp_top;
    }
    if (a->top == 0)
        a->neg = 0;
    a->flags &= ~BN_FLG_FIXED_TOP;
}

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    unsigned int i, m;
    unsigned int n;
    BN_ULONG l;
    BIGNUM *bn = NULL;

    if (ret == NULL)
        ret = bn = BN_new();
    if (ret == NULL)
        return NULL;
    /* Skip leading zero's. */
    for ( ; len > 0 && *s == 0; s++, len--)
        continue;
    n = len;
    if (n == 0) {
        ret->top = 0;
        return ret;
    }
    i = ((n - 1) / BN_BYTES) + 1;
    m = ((n - 1) % (BN_BYTES));
    if (bn_wexpand(ret, (int)i) == NULL) {
        BN_free(bn);
        return NULL;
    }
    ret->top = i;
    ret->neg = 0;
    l = 0;
    while (n--) {
        l = (l << 8L) | *(s++);
        if (m-- == 0) {
            ret->d[--i] = l;
            l = 0;
            m = BN_BYTES - 1;
        }
    }

    bn_correct_top(ret);
    return ret;
}

int BN_ucmp(const BIGNUM *a, const BIGNUM *b)
{
    int i;
    BN_ULONG t1, t2, *ap, *bp;

    i = a->top - b->top;
    if (i != 0)
        return i;
    ap = a->d;
    bp = b->d;
    for (i = a->top - 1; i >= 0; i--) {
        t1 = ap[i];
        t2 = bp[i];
        if (t1 != t2)
            return ((t1 > t2) ? 1 : -1);
    }
    return 0;
}

# define RSA_FLAG_NO_BLINDING            0x0080



#define BN_BLINDING_COUNTER     32
# define BN_BLINDING_NO_RECREATE 0x00000002

void BN_BLINDING_free(BN_BLINDING *r)
{
    if (r == NULL)
        return;
    BN_free(r->A);
    BN_free(r->Ai);
    BN_free(r->e);
    BN_free(r->mod);
    CRYPTO_free(r);
}

BIGNUM *BN_secure_new(void)
{
    BIGNUM *ret = BN_new();
    if (ret != NULL)
        ret->flags |= BN_FLG_SECURE;
    return ret;
}

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
{
    if (a == b)
        return a;
    if (bn_wexpand(a, b->top) == NULL)
        return NULL;

    if (b->top > 0)
        memcpy(a->d, b->d, sizeof(b->d[0]) * b->top);

    a->neg = b->neg;
    a->top = b->top;
    a->flags |= b->flags & BN_FLG_FIXED_TOP;
    return a;
}

BIGNUM *BN_dup(const BIGNUM *a)
{
    BIGNUM *t;

    if (a == NULL)
        return NULL;

    t = BN_get_flags(a, BN_FLG_SECURE) ? BN_secure_new() : BN_new();
    if (t == NULL)
        return NULL;
    if (!BN_copy(t, a)) {
        BN_free(t);
        return NULL;
    }

    return t;
}

# define BN_FLG_CONSTTIME        0x04
BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod)
{
    BN_BLINDING *ret = NULL;
    if ((ret = (BN_BLINDING *)CRYPTO_zalloc(sizeof(*ret))) == NULL) {
        eosio_assert(false,"BN_F_BN_BLINDING_NEW, ERR_R_MALLOC_FAILURE");
        return NULL;
    }

    if (A != NULL) {
        if ((ret->A = BN_dup(A)) == NULL)
            goto err;
    }

    if (Ai != NULL) {
        if ((ret->Ai = BN_dup(Ai)) == NULL)
            goto err;
    }

    if ((ret->mod = BN_dup(mod)) == NULL)
        goto err;

    if (BN_get_flags(mod, BN_FLG_CONSTTIME) != 0)
        BN_set_flags(ret->mod, BN_FLG_CONSTTIME);

    ret->counter = -1;
    return ret;

    err:
    BN_BLINDING_free(ret);
    return NULL;
}


int BN_is_bit_set(const BIGNUM *a, int n)
{
    int i, j;
    if (n < 0)
        return 0;
    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i)
        return 0;
    return (int)(((a->d[i]) >> j) & ((BN_ULONG)1));
}

#define BN_RAND_TOP_ANY    -1
#define BN_RAND_BOTTOM_ANY  0


static ENGINE_TABLE *rand_table = NULL;
static const int dummy_nid = 1;

static ENGINE *funct_ref;

static int random_status(void)
{
    return 1;
}


static RAND_METHOD rdrand_meth = {
        NULL,                       /* seed */
        NULL,//get_random_bytes,
        NULL,                       /* cleanup */
        NULL,                       /* add */
        NULL,//get_random_bytes,
        random_status,
};

const RAND_METHOD *RAND_get_rand_method(void)
{
    return &rdrand_meth;
}

typedef struct rand_drbg_st RAND_DRBG;
typedef enum drbg_status_e {
    DRBG_UNINITIALISED,
    DRBG_READY,
    DRBG_ERROR
} DRBG_STATUS;

typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX *ctx);
typedef struct hmac_ctx_st HMAC_CTX;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;


#define HMAC_MAX_MD_CBLOCK_SIZE     144

struct hmac_ctx_st {
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx;
    EVP_MD_CTX *i_ctx;
    EVP_MD_CTX *o_ctx;
    unsigned int key_length;
    unsigned char key[HMAC_MAX_MD_CBLOCK_SIZE];
};

struct evp_pkey_method_st {
    int pkey_id;
    int flags;
} /* EVP_PKEY_METHOD */ ;

struct evp_pkey_ctx_st {
    /* Method associated with this operation */
    const EVP_PKEY_METHOD *pmeth;
    /* Engine that implements this method or NULL if builtin */
    ENGINE *engine;
    /* Key: may be NULL */
    EVP_PKEY *pkey;
    /* Peer key for key agreement, may be NULL */
    EVP_PKEY *peerkey;
    /* Actual operation */
    int operation;
    /* Algorithm specific data */
    void *data;
    /* Application specific data */
    void *app_data;
    /* Keygen callback */
    EVP_PKEY_gen_cb *pkey_gencb;
    /* implementation specific keygen data */
    int *keygen_info;
    int keygen_info_count;
} /* EVP_PKEY_CTX */ ;

struct evp_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVP_MD_CTX *ctx);
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
    int (*cleanup) (EVP_MD_CTX *ctx);
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} /* EVP_MD */ ;


struct evp_md_ctx_st {
    const EVP_MD *digest;
    ENGINE *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
} /* EVP_MD_CTX */ ;


#define HASH_PRNG_MAX_SEEDLEN    (888/8)

typedef struct rand_drbg_hash_st {
    const EVP_MD *md;
    EVP_MD_CTX *ctx;
    size_t blocklen;
    unsigned char V[HASH_PRNG_MAX_SEEDLEN];
    unsigned char C[HASH_PRNG_MAX_SEEDLEN];
    /* Temporary value storage: should always exceed max digest length */
    unsigned char vtmp[HASH_PRNG_MAX_SEEDLEN];
} RAND_DRBG_HASH;


# define EVP_MAX_MD_SIZE                 64/* longest known is SHA512 */
# define EVP_MAX_KEY_LENGTH              64
# define EVP_MAX_IV_LENGTH               16
# define EVP_MAX_BLOCK_LENGTH            32
typedef struct rand_drbg_hmac_st {
    const EVP_MD *md;
    HMAC_CTX *ctx;
    size_t blocklen;
    unsigned char K[EVP_MAX_MD_SIZE];
    unsigned char V[EVP_MAX_MD_SIZE];
} RAND_DRBG_HMAC;


struct evp_cipher_st {
    int nid;
    int block_size;
    /* Default value for variable length ciphers */
    int key_len;
    int iv_len;
    /* Various flags */
    unsigned long flags;
    /* init key */
    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    /* cleanup ctx */
    int (*cleanup) (EVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Get parameters from a ASN1_TYPE */
    int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Miscellaneous operations */
    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data */
    void *app_data;
} /* EVP_CIPHER */ ;

typedef struct evp_cipher_st EVP_CIPHER;

# define EVP_MAX_BLOCK_LENGTH            32
# define EVP_MAX_IV_LENGTH               16
#   define PEM_FLAG_SECURE             0x1
#   define PEM_FLAG_EAY_COMPATIBLE     0x2

struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
};/* EVP_CIPHER_CTX */

/*
 * The state of a DRBG AES-CTR.
 */
typedef struct rand_drbg_ctr_st {
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER_CTX *ctx_df;
    const EVP_CIPHER *cipher;
    size_t keylen;
    unsigned char K[32];
    unsigned char V[16];
    /* Temporary block storage used by ctr_df */
    unsigned char bltmp[16];
    size_t bltmp_pos;
    unsigned char KX[48];
} RAND_DRBG_CTR;

typedef int (*RAND_DRBG_instantiate_fn)(RAND_DRBG *ctx,
                                        const unsigned char *ent,
                                        size_t entlen,
                                        const unsigned char *nonce,
                                        size_t noncelen,
                                        const unsigned char *pers,
                                        size_t perslen);
/* reseed */
typedef int (*RAND_DRBG_reseed_fn)(RAND_DRBG *ctx,
                                   const unsigned char *ent,
                                   size_t entlen,
                                   const unsigned char *adin,
                                   size_t adinlen);
/* generate output */
typedef int (*RAND_DRBG_generate_fn)(RAND_DRBG *ctx,
                                     unsigned char *out,
                                     size_t outlen,
                                     const unsigned char *adin,
                                     size_t adinlen);
/* uninstantiate */
typedef int (*RAND_DRBG_uninstantiate_fn)(RAND_DRBG *ctx);

typedef struct rand_drbg_method_st {
    RAND_DRBG_instantiate_fn instantiate;
    RAND_DRBG_reseed_fn reseed;
    RAND_DRBG_generate_fn generate;
    RAND_DRBG_uninstantiate_fn uninstantiate;
} RAND_DRBG_METHOD;


typedef size_t (*RAND_DRBG_get_entropy_fn)(RAND_DRBG *drbg,
                                           unsigned char **pout,
                                           int entropy, size_t min_len,
                                           size_t max_len,
                                           int prediction_resistance);
typedef void (*RAND_DRBG_cleanup_entropy_fn)(RAND_DRBG *ctx,
                                             unsigned char *out, size_t outlen);
typedef size_t (*RAND_DRBG_get_nonce_fn)(RAND_DRBG *drbg, unsigned char **pout,
                                         int entropy, size_t min_len,
                                         size_t max_len);
typedef void (*RAND_DRBG_cleanup_nonce_fn)(RAND_DRBG *drbg,
                                           unsigned char *out, size_t outlen);

int RAND_DRBG_set_callbacks(RAND_DRBG *drbg,
                            RAND_DRBG_get_entropy_fn get_entropy,
                            RAND_DRBG_cleanup_entropy_fn cleanup_entropy,
                            RAND_DRBG_get_nonce_fn get_nonce,
                            RAND_DRBG_cleanup_nonce_fn cleanup_nonce);

struct rand_drbg_st {
    RAND_DRBG *parent;
    int secure; /* 1: allocated on the secure heap, 0: otherwise */
    int type; /* the nid of the underlying algorithm */
    int fork_count;
    unsigned short flags; /* various external flags */
    struct rand_pool_st *seed_pool;
    struct rand_pool_st *adin_pool;
    int strength;
    size_t max_request;
    size_t min_entropylen, max_entropylen;
    size_t min_noncelen, max_noncelen;
    size_t max_perslen, max_adinlen;
    unsigned int reseed_gen_counter;
    unsigned int reseed_interval;
    time_t reseed_time;
    time_t reseed_time_interval;
    volatile unsigned int reseed_prop_counter;
    unsigned int reseed_next_counter;

    size_t seedlen;
    DRBG_STATUS state;

    /* Application data, mainly used in the KATs. */
    CRYPTO_EX_DATA ex_data;

    /* Implementation specific data */
    union {
        RAND_DRBG_CTR ctr;
        RAND_DRBG_HASH hash;
        RAND_DRBG_HMAC hmac;
    } data;

    /* Implementation specific methods */
    RAND_DRBG_METHOD *meth;

    /* Callback functions.  See comments in rand_lib.c */
    RAND_DRBG_get_entropy_fn get_entropy;
    RAND_DRBG_cleanup_entropy_fn cleanup_entropy;
    RAND_DRBG_get_nonce_fn get_nonce;
    RAND_DRBG_cleanup_nonce_fn cleanup_nonce;
};



RAND_METHOD *RAND_OpenSSL(void)
{
    return &rdrand_meth;
}

int RAND_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->bytes != NULL)
        return meth->bytes(buf, num);

    eosio_assert(false,(char *)"RAND_F_RAND_BYTES, RAND_R_FUNC_NOT_IMPLEMENTED");
    return -1;
}

struct rand_pool_st {
    unsigned char *buffer;  /* points to the beginning of the random pool */
    size_t len; /* current number of random bytes contained in the pool */

    int attached;  /* true pool was attached to existing buffer */

    size_t min_len; /* minimum number of random bytes requested */
    size_t max_len; /* maximum number of random bytes (allocated buffer size) */
    size_t entropy; /* current entropy count in bits */
    size_t entropy_requested; /* requested entropy count in bits */
};

typedef struct rand_pool_st RAND_POOL;
# define TWO32TO64(a, b) ((((uint64_t)(a)) << 32) + (b))
size_t rand_pool_length(RAND_POOL *pool)
{
    return pool->len;
}


# define RAND_DRBG_STRENGTH             256
# define RAND_POOL_FACTOR        256
# define RAND_POOL_MAX_LENGTH    (RAND_POOL_FACTOR * \
                                  3 * (RAND_DRBG_STRENGTH / 16))

RAND_POOL *rand_pool_new(int entropy_requested, size_t min_len, size_t max_len)
{
    RAND_POOL *pool = (RAND_POOL *)CRYPTO_zalloc(sizeof(*pool));

    if (pool == NULL) {
        eosio_assert(false, (char *)"RAND_F_RAND_POOL_NEW, ERR_R_MALLOC_FAILURE");
        return NULL;
    }

    pool->min_len = min_len;
    pool->max_len = (max_len > RAND_POOL_MAX_LENGTH) ?
                    RAND_POOL_MAX_LENGTH : max_len;

    pool->buffer = (unsigned char *)CRYPTO_zalloc(pool->max_len);
    if (pool->buffer == NULL) {
        goto err;
    }

    pool->entropy_requested = entropy_requested;

    return pool;

    err:
    CRYPTO_free(pool);
    return NULL;
}


unsigned char *rand_pool_detach(RAND_POOL *pool)
{
    unsigned char *ret = pool->buffer;
    pool->buffer = NULL;
    pool->entropy = 0;
    return ret;
}

int RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen);


static uint64_t get_timer_bits(void)
{
//    struct timeval tv;
//
//    if (gettimeofday(&tv, NULL) == 0)
//        return TWO32TO64(tv.tv_sec, tv.tv_usec);
//

    return now();
}

int rand_pool_add(RAND_POOL *pool,
                  const unsigned char *buffer, size_t len, size_t entropy);



CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void)
{
    return now();
}


int rand_pool_add_additional_data(RAND_POOL *pool)
{
    struct {
        CRYPTO_THREAD_ID tid;
        uint64_t time;
    } data = { 0 };

    /*
     * Add some noise from the thread id and a high resolution timer.
     * The thread id adds a little randomness if the drbg is accessed
     * concurrently (which is the case for the <master> drbg).
     */
    data.tid = CRYPTO_THREAD_get_current_id();
    data.time = get_timer_bits();

    return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}


size_t rand_drbg_get_additional_data(RAND_POOL *pool, unsigned char **pout)
{
    size_t ret = 0;

    if (rand_pool_add_additional_data(pool) == 0)
        goto err;

    ret = rand_pool_length(pool);
    *pout = rand_pool_detach(pool);

    err:
    return ret;
}

void rand_pool_reattach(RAND_POOL *pool, unsigned char *buffer)
{
    pool->buffer = buffer;
    OPENSSL_cleanse(pool->buffer, pool->len);
    pool->len = 0;
}


void rand_drbg_cleanup_additional_data(RAND_POOL *pool, unsigned char *out)
{
    rand_pool_reattach(pool, out);
}


int RAND_DRBG_bytes(RAND_DRBG *drbg, unsigned char *out, size_t outlen)
{
    unsigned char *additional = NULL;
    size_t additional_len;
    size_t chunk;
    size_t ret = 0;

    if (drbg->adin_pool == NULL) {
        if (drbg->type == 0)
            goto err;
        drbg->adin_pool = rand_pool_new(0, 0, drbg->max_adinlen);
        if (drbg->adin_pool == NULL)
            goto err;
    }

    additional_len = rand_drbg_get_additional_data(drbg->adin_pool,
                                                   &additional);

    for ( ; outlen > 0; outlen -= chunk, out += chunk) {
        chunk = outlen;
        if (chunk > drbg->max_request)
            chunk = drbg->max_request;
        ret = RAND_DRBG_generate(drbg, out, chunk, 0, additional, additional_len);
        if (!ret)
            goto err;
    }
    ret = 1;

    err:
    if (additional != NULL)
        rand_drbg_cleanup_additional_data(drbg->adin_pool, additional);

    return ret;
}

size_t rand_pool_entropy_needed(RAND_POOL *pool)
{
    if (pool->entropy < pool->entropy_requested)
        return pool->entropy_requested - pool->entropy;

    return 0;
}


#define ENTROPY_TO_BYTES(bits, entropy_factor) \
    (((bits) * (entropy_factor) + 7) / 8)


size_t rand_pool_bytes_needed(RAND_POOL *pool, unsigned int entropy_factor)
{
    size_t bytes_needed;
    size_t entropy_needed = rand_pool_entropy_needed(pool);

    if (entropy_factor < 1) {
        eosio_assert(false, (char *)"RAND_F_RAND_POOL_BYTES_NEEDED, RAND_R_ARGUMENT_OUT_OF_RANGE");
        return 0;
    }

    bytes_needed = ENTROPY_TO_BYTES(entropy_needed, entropy_factor);

    if (bytes_needed > pool->max_len - pool->len) {
        /* not enough space left */
        eosio_assert(false, (char *)"RAND_F_RAND_POOL_BYTES_NEEDED, RAND_R_RANDOM_POOL_OVERFLOW");
        return 0;
    }

    if (pool->len < pool->min_len &&
        bytes_needed < pool->min_len - pool->len)
        /* to meet the min_len requirement */
        bytes_needed = pool->min_len - pool->len;

    return bytes_needed;
}

unsigned char *rand_pool_add_begin(RAND_POOL *pool, size_t len)
{
    if (len == 0)
        return NULL;

    if (len > pool->max_len - pool->len) {
        eosio_assert(false, (char *)"RAND_F_RAND_POOL_ADD_BEGIN, RAND_R_RANDOM_POOL_OVERFLOW");
        return NULL;
    }

    if (pool->buffer == NULL) {
        eosio_assert(false, (char *)"RAND_F_RAND_POOL_ADD_BEGIN, ERR_R_INTERNAL_ERROR");
        return 0;
    }

    return pool->buffer + pool->len;
}


RAND_POOL *rand_pool_attach(const unsigned char *buffer, size_t len,
                            size_t entropy)
{
    RAND_POOL *pool = (RAND_POOL *)CRYPTO_zalloc(sizeof(*pool));

    if (pool == NULL) {
        eosio_assert(false, (char *)"RAND_F_RAND_POOL_ATTACH, ERR_R_MALLOC_FAILURE");
        return NULL;
    }

    pool->buffer = (unsigned char *) buffer;
    pool->len = len;

    pool->attached = 1;

    pool->min_len = pool->max_len = pool->len;
    pool->entropy = entropy;

    return pool;
}

void CRYPTO_clear_free(void *str, size_t num);

void rand_pool_free(RAND_POOL *pool)
{
    if (pool == NULL)
        return;

    if (!pool->attached)
        CRYPTO_clear_free(pool->buffer, pool->max_len);
    CRYPTO_free(pool);
}


#  define tsan_load(ptr) (*(ptr))
#  define tsan_store(ptr, val) (*(ptr) = (val))
int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                      ENGINE *impl, const unsigned char *key,
                      const unsigned char *iv, int enc);



int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}

# define         EVP_CIPH_FLAG_CUSTOM_CIPHER     0x100000
# define         EVP_CIPH_FLAG_LENGTH_BITS       0x2000
# define         EVP_CIPH_NO_PADDING             0x100
# define AES_BLOCK_SIZE 16
int is_partially_overlapping(const void *ptr1, const void *ptr2, int len)
{
    size_t diff = (size_t)ptr1-(size_t)ptr2;

    int overlapped = (len > 0) & (diff != 0) & ((diff < (size_t)len) |
                                                (diff > (0 - (size_t)len)));

    return overlapped;
}


int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int i, j, bl, cmpl = inl;

    if (EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS))
        cmpl = (cmpl + 7) / 8;

    bl = ctx->cipher->block_size;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        /* If block size > 1 then the cipher will have to do this check */
        if (bl == 1 && is_partially_overlapping(out, in, cmpl)) {
            eosio_assert(false, (char *)"EVP_F_EVP_ENCRYPTUPDATE, EVP_R_PARTIALLY_OVERLAPPING");
            return 0;
        }

        i = ctx->cipher->do_cipher(ctx, out, in, inl);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        return inl == 0;
    }
    if (is_partially_overlapping(out + ctx->buf_len, in, cmpl)) {
        eosio_assert(false, (char *)"EVP_F_EVP_ENCRYPTUPDATE, EVP_R_PARTIALLY_OVERLAPPING");
        return 0;
    }

    if (ctx->buf_len == 0 && (inl & (ctx->block_mask)) == 0) {
        if (ctx->cipher->do_cipher(ctx, out, in, inl)) {
            *outl = inl;
            return 1;
        } else {
            *outl = 0;
            return 0;
        }
    }
    i = ctx->buf_len;
    if(bl > (int)sizeof(ctx->buf)){
        eosio_assert(false, (char *)"bl > (int)sizeof(ctx->buf)");
    }
    if (i != 0) {
        if (bl - i > inl) {
            memcpy(&(ctx->buf[i]), in, inl);
            ctx->buf_len += inl;
            *outl = 0;
            return 1;
        } else {
            j = bl - i;
            memcpy(&(ctx->buf[i]), in, j);
            inl -= j;
            in += j;
            if (!ctx->cipher->do_cipher(ctx, out, ctx->buf, bl))
                return 0;
            out += bl;
            *outl = bl;
        }
    } else
        *outl = 0;
    i = inl & (bl - 1);
    inl -= i;
    if (inl > 0) {
        if (!ctx->cipher->do_cipher(ctx, out, in, inl))
            return 0;
        *outl += inl;
    }

    if (i != 0)
        memcpy(ctx->buf, &(in[inl]), i);
    ctx->buf_len = i;
    return 1;
}

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int fix_len, cmpl = inl;
    unsigned int b;

    b = ctx->cipher->block_size;

    if (EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS))
        cmpl = (cmpl + 7) / 8;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        if (b == 1 && is_partially_overlapping(out, in, cmpl)) {
            eosio_assert(false, (char *)"EVP_F_EVP_DECRYPTUPDATE, EVP_R_PARTIALLY_OVERLAPPING");
            return 0;
        }

        fix_len = ctx->cipher->do_cipher(ctx, out, in, inl);
        if (fix_len < 0) {
            *outl = 0;
            return 0;
        } else
            *outl = fix_len;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        return inl == 0;
    }

    if (ctx->flags & EVP_CIPH_NO_PADDING)
        return EVP_EncryptUpdate(ctx, out, outl, in, inl);

    if(b > sizeof(ctx->final)){
        eosio_assert(false, (char *)"b > sizeof(ctx->final)");
    }

    if (ctx->final_used) {
        /* see comment about PTRDIFF_T comparison above */
        if (((size_t)out == (size_t)in)
            || is_partially_overlapping(out, in, b)) {
            eosio_assert(false, (char *)"EVP_F_EVP_DECRYPTUPDATE, EVP_R_PARTIALLY_OVERLAPPING");
            return 0;
        }
        memcpy(out, ctx->final, b);
        out += b;
        fix_len = 1;
    } else
        fix_len = 0;

    if (!EVP_EncryptUpdate(ctx, out, outl, in, inl))
        return 0;

    /*
     * if we have 'decrypted' a multiple of block size, make sure we have a
     * copy of this last block
     */
    if (b > 1 && !ctx->buf_len) {
        *outl -= b;
        ctx->final_used = 1;
        memcpy(ctx->final, &out[*outl], b);
    } else
        ctx->final_used = 0;

    if (fix_len)
        *outl += b;

    return 1;
}

int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl)
{
    if (ctx->encrypt)
        return EVP_EncryptUpdate(ctx, out, outl, in, inl);
    else
        return EVP_DecryptUpdate(ctx, out, outl, in, inl);
}

static void inc_128(RAND_DRBG_CTR *ctr)
{
    int i;
    unsigned char c;
    unsigned char *p = &ctr->V[15];

    for (i = 0; i < 16; i++, p--) {
        c = *p;
        c++;
        *p = c;
        if (c != 0) {
            /* If we didn't wrap around, we're done. */
            break;
        }
    }
}


static void ctr_XOR(RAND_DRBG_CTR *ctr, const unsigned char *in, size_t inlen)
{
    size_t i, n;

    if (in == NULL || inlen == 0)
        return;

    /*
     * Any zero padding will have no effect on the result as we
     * are XORing. So just process however much input we have.
     */
    n = inlen < ctr->keylen ? inlen : ctr->keylen;
    for (i = 0; i < n; i++)
        ctr->K[i] ^= in[i];
    if (inlen <= ctr->keylen)
        return;

    n = inlen - ctr->keylen;
    if (n > 16) {
        /* Should never happen */
        n = 16;
    }
    for (i = 0; i < n; i++)
        ctr->V[i] ^= in[i + ctr->keylen];
}


static int ctr_BCC_block(RAND_DRBG_CTR *ctr, unsigned char *out,
                         const unsigned char *in)
{
    int i, outlen = AES_BLOCK_SIZE;

    for (i = 0; i < 16; i++)
        out[i] ^= in[i];

    if (!EVP_CipherUpdate(ctr->ctx_df, out, &outlen, out, AES_BLOCK_SIZE)
        || outlen != AES_BLOCK_SIZE)
        return 0;
    return 1;
}

# define RAND_DRBG_FLAG_CTR_NO_DF            0x1


static int ctr_BCC_blocks(RAND_DRBG_CTR *ctr, const unsigned char *in)
{
    if (!ctr_BCC_block(ctr, ctr->KX, in)
        || !ctr_BCC_block(ctr, ctr->KX + 16, in))
        return 0;
    if (ctr->keylen != 16 && !ctr_BCC_block(ctr, ctr->KX + 32, in))
        return 0;
    return 1;
}

static int ctr_BCC_final(RAND_DRBG_CTR *ctr)
{
    if (ctr->bltmp_pos) {
        memset(ctr->bltmp + ctr->bltmp_pos, 0, 16 - ctr->bltmp_pos);
        if (!ctr_BCC_blocks(ctr, ctr->bltmp))
            return 0;
    }
    return 1;
}

static int ctr_BCC_update(RAND_DRBG_CTR *ctr,
                         const unsigned char *in, size_t inlen)
{
    if (in == NULL || inlen == 0)
        return 1;

    /* If we have partial block handle it first */
    if (ctr->bltmp_pos) {
        size_t left = 16 - ctr->bltmp_pos;

        /* If we now have a complete block process it */
        if (inlen >= left) {
            memcpy(ctr->bltmp + ctr->bltmp_pos, in, left);
            if (!ctr_BCC_blocks(ctr, ctr->bltmp))
                return 0;
            ctr->bltmp_pos = 0;
            inlen -= left;
            in += left;
        }
    }

    /* Process zero or more complete blocks */
    for (; inlen >= 16; in += 16, inlen -= 16) {
        if (!ctr_BCC_blocks(ctr, in))
            return 0;
    }

    /* Copy any remaining partial block to the temporary buffer */
    if (inlen > 0) {
        memcpy(ctr->bltmp + ctr->bltmp_pos, in, inlen);
        ctr->bltmp_pos += inlen;
    }
    return 1;
}

static int ctr_BCC_init(RAND_DRBG_CTR *ctr)
{
    memset(ctr->KX, 0, 48);
    memset(ctr->bltmp, 0, 16);
    if (!ctr_BCC_block(ctr, ctr->KX, ctr->bltmp))
        return 0;
    ctr->bltmp[3] = 1;
    if (!ctr_BCC_block(ctr, ctr->KX + 16, ctr->bltmp))
        return 0;
    if (ctr->keylen != 16) {
        ctr->bltmp[3] = 2;
        if (!ctr_BCC_block(ctr, ctr->KX + 32, ctr->bltmp))
            return 0;
    }
    return 1;
}


static int ctr_df(RAND_DRBG_CTR *ctr,
                  const unsigned char *in1, size_t in1len,
                  const unsigned char *in2, size_t in2len,
                  const unsigned char *in3, size_t in3len)
{
    static unsigned char c80 = 0x80;
    size_t inlen;
    unsigned char *p = ctr->bltmp;
    int outlen = AES_BLOCK_SIZE;

    if (!ctr_BCC_init(ctr))
        return 0;
    if (in1 == NULL)
        in1len = 0;
    if (in2 == NULL)
        in2len = 0;
    if (in3 == NULL)
        in3len = 0;
    inlen = in1len + in2len + in3len;
    /* Initialise L||N in temporary block */
    *p++ = (inlen >> 24) & 0xff;
    *p++ = (inlen >> 16) & 0xff;
    *p++ = (inlen >> 8) & 0xff;
    *p++ = inlen & 0xff;

    /* NB keylen is at most 32 bytes */
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p = (unsigned char)((ctr->keylen + 16) & 0xff);
    ctr->bltmp_pos = 8;
    if (!ctr_BCC_update(ctr, in1, in1len)
        || !ctr_BCC_update(ctr, in2, in2len)
        || !ctr_BCC_update(ctr, in3, in3len)
        || !ctr_BCC_update(ctr, &c80, 1)
        || !ctr_BCC_final(ctr))
        return 0;
    /* Set up key K */
    if (!EVP_CipherInit_ex(ctr->ctx, ctr->cipher, NULL, ctr->KX, NULL, 1))
        return 0;
    /* X follows key K */
    if (!EVP_CipherUpdate(ctr->ctx, ctr->KX, &outlen, ctr->KX + ctr->keylen,
                          AES_BLOCK_SIZE)
        || outlen != AES_BLOCK_SIZE)
        return 0;
    if (!EVP_CipherUpdate(ctr->ctx, ctr->KX + 16, &outlen, ctr->KX,
                          AES_BLOCK_SIZE)
        || outlen != AES_BLOCK_SIZE)
        return 0;
    if (ctr->keylen != 16)
        if (!EVP_CipherUpdate(ctr->ctx, ctr->KX + 32, &outlen, ctr->KX + 16,
                              AES_BLOCK_SIZE)
            || outlen != AES_BLOCK_SIZE)
            return 0;
    return 1;
}


static int ctr_update(RAND_DRBG *drbg,
                      const unsigned char *in1, size_t in1len,
                      const unsigned char *in2, size_t in2len,
                      const unsigned char *nonce, size_t noncelen)
{
    RAND_DRBG_CTR *ctr = &drbg->data.ctr;
    int outlen = AES_BLOCK_SIZE;

    /* correct key is already set up. */
    inc_128(ctr);
    if (!EVP_CipherUpdate(ctr->ctx, ctr->K, &outlen, ctr->V, AES_BLOCK_SIZE)
        || outlen != AES_BLOCK_SIZE)
        return 0;

    /* If keylen longer than 128 bits need extra encrypt */
    if (ctr->keylen != 16) {
        inc_128(ctr);
        if (!EVP_CipherUpdate(ctr->ctx, ctr->K+16, &outlen, ctr->V,
                              AES_BLOCK_SIZE)
            || outlen != AES_BLOCK_SIZE)
            return 0;
    }
    inc_128(ctr);
    if (!EVP_CipherUpdate(ctr->ctx, ctr->V, &outlen, ctr->V, AES_BLOCK_SIZE)
        || outlen != AES_BLOCK_SIZE)
        return 0;

    /* If 192 bit key part of V is on end of K */
    if (ctr->keylen == 24) {
        memcpy(ctr->V + 8, ctr->V, 8);
        memcpy(ctr->V, ctr->K + 24, 8);
    }

    if ((drbg->flags & RAND_DRBG_FLAG_CTR_NO_DF) == 0) {
        /* If no input reuse existing derived value */
        if (in1 != NULL || nonce != NULL || in2 != NULL)
            if (!ctr_df(ctr, in1, in1len, nonce, noncelen, in2, in2len))
                return 0;
        /* If this a reuse input in1len != 0 */
        if (in1len)
            ctr_XOR(ctr, ctr->KX, drbg->seedlen);
    } else {
        ctr_XOR(ctr, in1, in1len);
        ctr_XOR(ctr, in2, in2len);
    }

    if (!EVP_CipherInit_ex(ctr->ctx, ctr->cipher, NULL, ctr->K, NULL, 1))
        return 0;
    return 1;
}

static int drbg_ctr_instantiate(RAND_DRBG *drbg,
                                const unsigned char *entropy, size_t entropylen,
                                const unsigned char *nonce, size_t noncelen,
                                const unsigned char *pers, size_t perslen)
{
    RAND_DRBG_CTR *ctr = &drbg->data.ctr;

    if (entropy == NULL)
        return 0;

    memset(ctr->K, 0, sizeof(ctr->K));
    memset(ctr->V, 0, sizeof(ctr->V));
    if (!EVP_CipherInit_ex(ctr->ctx, ctr->cipher, NULL, ctr->K, NULL, 1))
        return 0;
    if (!ctr_update(drbg, entropy, entropylen, pers, perslen, nonce, noncelen))
        return 0;
    return 1;
}

int RAND_DRBG_instantiate(RAND_DRBG *drbg,
                          const unsigned char *pers, size_t perslen)
{
    unsigned char *nonce = NULL, *entropy = NULL;
    size_t noncelen = 0, entropylen = 0;
    size_t min_entropy = drbg->strength;
    size_t min_entropylen = drbg->min_entropylen;
    size_t max_entropylen = drbg->max_entropylen;

    if (perslen > drbg->max_perslen) {
        goto end;
    }

    if (drbg->meth == NULL) {
        goto end;
    }

    if (drbg->state != DRBG_UNINITIALISED) {
        goto end;
    }

    drbg->state = DRBG_ERROR;

    if (drbg->min_noncelen > 0 && drbg->get_nonce == NULL) {
        min_entropy += drbg->strength / 2;
        min_entropylen += drbg->min_noncelen;
        max_entropylen += drbg->max_noncelen;
    }

    drbg->reseed_next_counter = tsan_load(&drbg->reseed_prop_counter);
    if (drbg->reseed_next_counter) {
        drbg->reseed_next_counter++;
        if(!drbg->reseed_next_counter)
            drbg->reseed_next_counter = 1;
    }

    if (drbg->get_entropy != NULL)
        entropylen = drbg->get_entropy(drbg, &entropy, min_entropy,
                                       min_entropylen, max_entropylen, 0);
    if (entropylen < min_entropylen
        || entropylen > max_entropylen) {
        goto end;
    }

    if (drbg->min_noncelen > 0 && drbg->get_nonce != NULL) {
        noncelen = drbg->get_nonce(drbg, &nonce, drbg->strength / 2,
                                   drbg->min_noncelen, drbg->max_noncelen);
        if (noncelen < drbg->min_noncelen || noncelen > drbg->max_noncelen) {
            goto end;
        }
    }

    if (!drbg_ctr_instantiate(drbg, entropy, entropylen,
                                 nonce, noncelen, pers, perslen)) {
        goto end;
    }

    drbg->state = DRBG_READY;
    drbg->reseed_gen_counter = 1;
    drbg->reseed_time = now();
    tsan_store(&drbg->reseed_prop_counter, drbg->reseed_next_counter);

    end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entropylen);
    if (nonce != NULL && drbg->cleanup_nonce != NULL)
        drbg->cleanup_nonce(drbg, nonce, noncelen);
    if (drbg->state == DRBG_READY)
        return 1;
    return 0;
}


static const char ossl_pers_string[] = "OpenSSL NIST SP 800-90A DRBG";
int rand_drbg_restart(RAND_DRBG *drbg,
                      const unsigned char *buffer, size_t len, size_t entropy)
{
    int reseeded = 0;
    const unsigned char *adin = NULL;
    size_t adinlen = 0;

    if (drbg->seed_pool != NULL) {
        eosio_assert(false, (char *)"RAND_F_RAND_DRBG_RESTART, ERR_R_INTERNAL_ERROR");
        drbg->state = DRBG_ERROR;
        rand_pool_free(drbg->seed_pool);
        drbg->seed_pool = NULL;
        return 0;
    }

    if (buffer != NULL) {
        if (entropy > 0) {
            if (drbg->max_entropylen < len) {
                eosio_assert(false, (char *)"RAND_F_RAND_DRBG_RESTART,RAND_R_ENTROPY_INPUT_TOO_LONG");
                drbg->state = DRBG_ERROR;
                return 0;
            }

            if (entropy > 8 * len) {
                eosio_assert(false, (char *)"RAND_F_RAND_DRBG_RESTART, RAND_R_ENTROPY_OUT_OF_RANGE");
                drbg->state = DRBG_ERROR;
                return 0;
            }

            /* will be picked up by the rand_drbg_get_entropy() callback */
            drbg->seed_pool = rand_pool_attach(buffer, len, entropy);
            if (drbg->seed_pool == NULL)
                return 0;
        } else {
            if (drbg->max_adinlen < len) {
                eosio_assert(false, (char *)"RAND_F_RAND_DRBG_RESTART,RAND_R_ADDITIONAL_INPUT_TOO_LONG");
                drbg->state = DRBG_ERROR;
                return 0;
            }
            adin = buffer;
            adinlen = len;
        }
    }

    /* repair uninitialized state */
    if (drbg->state == DRBG_UNINITIALISED) {
        /* reinstantiate drbg */
        RAND_DRBG_instantiate(drbg,
                              (const unsigned char *) ossl_pers_string,
                              sizeof(ossl_pers_string) - 1);
        /* already reseeded. prevent second reseeding below */
        reseeded = (drbg->state == DRBG_READY);
    }

    /* refresh current state if entropy or additional input has been provided */
    if (drbg->state == DRBG_READY) {
        eosio_assert(false, (char *)"drbg->state == DRBG_READY");
//        if (adin != NULL) {
//            drbg->meth->reseed(drbg, adin, adinlen, NULL, 0);
//        } else if (reseeded == 0) {
//            /* do a full reseeding if it has not been done yet above */
//            RAND_DRBG_reseed(drbg, NULL, 0, 0);
//        }
    }

    rand_pool_free(drbg->seed_pool);
    drbg->seed_pool = NULL;

    return drbg->state == DRBG_READY;
}


int rand_fork_count;

static int drbg_ctr_generate(RAND_DRBG *drbg,
                             unsigned char *out, size_t outlen,
                             const unsigned char *adin, size_t adinlen)
{
    RAND_DRBG_CTR *ctr = &drbg->data.ctr;

    if (adin != NULL && adinlen != 0) {
        if (!ctr_update(drbg, adin, adinlen, NULL, 0, NULL, 0))
            return 0;
        /* This means we reuse derived value */
        if ((drbg->flags & RAND_DRBG_FLAG_CTR_NO_DF) == 0) {
            adin = NULL;
            adinlen = 1;
        }
    } else {
        adinlen = 0;
    }

    for ( ; ; ) {
        int outl = AES_BLOCK_SIZE;

        inc_128(ctr);
        if (outlen < 16) {
            /* Use K as temp space as it will be updated */
            if (!EVP_CipherUpdate(ctr->ctx, ctr->K, &outl, ctr->V,
                                  AES_BLOCK_SIZE)
                || outl != AES_BLOCK_SIZE)
                return 0;
            memcpy(out, ctr->K, outlen);
            break;
        }
        if (!EVP_CipherUpdate(ctr->ctx, out, &outl, ctr->V, AES_BLOCK_SIZE)
            || outl != AES_BLOCK_SIZE)
            return 0;
        out += 16;
        outlen -= 16;
        if (outlen == 0)
            break;
    }

    if (!ctr_update(drbg, adin, adinlen, NULL, 0, NULL, 0))
        return 0;
    return 1;
}

int RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen)
{
    int reseed_required = 0;

    if (drbg->state != DRBG_READY) {
        /* try to recover from previous errors */
        rand_drbg_restart(drbg, NULL, 0, 0);

        if (drbg->state == DRBG_ERROR) {
            eosio_assert(false, (char *)"RAND_F_RAND_DRBG_GENERATE, RAND_R_IN_ERROR_STATE");
            return 0;
        }
        if (drbg->state == DRBG_UNINITIALISED) {
            eosio_assert(false, (char *)"RAND_F_RAND_DRBG_GENERATE, RAND_R_NOT_INSTANTIATED");
            return 0;
        }
    }

    if (outlen > drbg->max_request) {
        eosio_assert(false, (char *)"RAND_F_RAND_DRBG_GENERATE, RAND_R_REQUEST_TOO_LARGE_FOR_DRBG");
        return 0;
    }
    if (adinlen > drbg->max_adinlen) {
        eosio_assert(false, (char *)"RAND_F_RAND_DRBG_GENERATE, RAND_R_ADDITIONAL_INPUT_TOO_LONG");
        return 0;
    }

    if (drbg->fork_count != rand_fork_count) {
        drbg->fork_count = rand_fork_count;
        reseed_required = 1;
    }

    if (drbg->reseed_interval > 0) {
        if (drbg->reseed_gen_counter > drbg->reseed_interval)
            reseed_required = 1;
    }
    if (drbg->reseed_time_interval > 0) {
        time_t now = time(NULL);
        if (now < drbg->reseed_time
            || now - drbg->reseed_time >= drbg->reseed_time_interval)
            reseed_required = 1;
    }
    if (drbg->parent != NULL) {
        unsigned int reseed_counter = tsan_load(&drbg->reseed_prop_counter);
        if (reseed_counter > 0
            && tsan_load(&drbg->parent->reseed_prop_counter)
               != reseed_counter)
            reseed_required = 1;
    }

    if (!drbg_ctr_generate(drbg, out, outlen, adin, adinlen)) {
        drbg->state = DRBG_ERROR;
        eosio_assert(false, (char *)"RAND_F_RAND_DRBG_GENERATE, RAND_R_GENERATE_ERROR");
        return 0;
    }

    drbg->reseed_gen_counter++;

    return 1;
}

int rand_pool_add_end(RAND_POOL *pool, size_t len, size_t entropy)
{
    if (len > pool->max_len - pool->len) {
        eosio_assert(false, (char *)"RAND_F_RAND_POOL_ADD_END, RAND_R_RANDOM_POOL_OVERFLOW");
        return 0;
    }

    if (len > 0) {
        pool->len += len;
        pool->entropy += entropy;
    }

    return 1;
}

size_t rand_pool_entropy_available(RAND_POOL *pool)
{
    if (pool->entropy < pool->entropy_requested)
        return 0;

    if (pool->len < pool->min_len)
        return 0;

    return pool->entropy;
}

static ssize_t syscall_random(void *buf, size_t buflen)
{
    unsigned int tmp_time= now();
    memcpy(buf,&tmp_time,buflen);
    return 1;
}

size_t rand_pool_acquire_entropy(RAND_POOL *pool)
{
    size_t bytes_needed;
    size_t entropy_available = 0;
    unsigned char *buffer;

    ssize_t bytes;
    /* Maximum allowed number of consecutive unsuccessful attempts */
    int attempts = 3;

    bytes_needed = rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
    while (bytes_needed != 0 && attempts-- > 0) {
        buffer = rand_pool_add_begin(pool, bytes_needed);
        bytes = syscall_random(buffer, bytes_needed);
        if (bytes > 0) {
            rand_pool_add_end(pool, bytes, 8 * bytes);
            bytes_needed -= bytes;
            attempts = 3; /* reset counter after successful attempt */
        } else if (bytes < 0 && errno != EINTR) {
            break;
        }
    }

    entropy_available = rand_pool_entropy_available(pool);
    if (entropy_available > 0)
        return entropy_available;

    return 0;
}


size_t rand_drbg_get_entropy(RAND_DRBG *drbg,
                             unsigned char **pout,
                             int entropy, size_t min_len, size_t max_len,
                             int prediction_resistance)
{
    size_t ret = 0;
    size_t entropy_available = 0;
    RAND_POOL *pool;

    if (drbg->parent && drbg->strength > drbg->parent->strength) {
        /*
         * We currently don't support the algorithm from NIST SP 800-90C
         * 10.1.2 to use a weaker DRBG as source
         */
        eosio_assert(false, (char *)"RAND_F_RAND_DRBG_GET_ENTROPY, RAND_R_PARENT_STRENGTH_TOO_WEAK");
        return 0;
    }

    if (drbg->seed_pool != NULL) {
        pool = drbg->seed_pool;
        pool->entropy_requested = entropy;
    } else {
        pool = rand_pool_new(entropy, min_len, max_len);
        if (pool == NULL)
            return 0;
    }

    if (drbg->parent) {
        size_t bytes_needed = rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
        unsigned char *buffer = rand_pool_add_begin(pool, bytes_needed);

        if (buffer != NULL) {
            size_t bytes = 0;

            /*
             * Get random from parent, include our state as additional input.
             * Our lock is already held, but we need to lock our parent before
             * generating bits from it. (Note: taking the lock will be a no-op
             * if locking if drbg->parent->lock == NULL.)
             */
            if (RAND_DRBG_generate(drbg->parent,
                                   buffer, bytes_needed,
                                   prediction_resistance,
                                   NULL, 0) != 0)
                bytes = bytes_needed;
            drbg->reseed_next_counter
                    = tsan_load(&drbg->parent->reseed_prop_counter);

            rand_pool_add_end(pool, bytes, 8 * bytes);
            entropy_available = rand_pool_entropy_available(pool);
        }

    } else {
        if (prediction_resistance) {
            goto err;
        }

        /* Get entropy by polling system entropy sources. */
        entropy_available = rand_pool_acquire_entropy(pool);
    }

    if (entropy_available > 0) {
        ret   = rand_pool_length(pool);
        *pout = rand_pool_detach(pool);
    }

    err:
    if (drbg->seed_pool == NULL)
        rand_pool_free(pool);
    return ret;
}


void rand_drbg_cleanup_entropy(RAND_DRBG *drbg,
                               unsigned char *out, size_t outlen)
{
    if (drbg->seed_pool == NULL)
        CRYPTO_clear_free(out, outlen);
}


int rand_pool_add(RAND_POOL *pool,
                  const unsigned char *buffer, size_t len, size_t entropy)
{
    if (len > pool->max_len - pool->len) {
        eosio_assert(false, (char *)"RAND_F_RAND_POOL_ADD, RAND_R_ENTROPY_INPUT_TOO_LONG");
        return 0;
    }

    if (pool->buffer == NULL) {
        eosio_assert(false, (char *)"RAND_F_RAND_POOL_ADD, ERR_R_INTERNAL_ERROR");
        return 0;
    }

    if (len > 0) {
        memcpy(pool->buffer + pool->len, buffer, len);
        pool->len += len;
        pool->entropy += entropy;
    }

    return 1;
}

static void *rand_nonce_lock;
static int rand_nonce_count;

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock)
{
    *val += amount;
    *ret  = *val;

    return 1;
}

static uint64_t get_time_stamp(void)
{
    return now();
}

int rand_pool_add_nonce_data(RAND_POOL *pool)
{
    struct {
        unsigned int pid;
        CRYPTO_THREAD_ID tid;
        uint64_t time;
    } data = { 0 };

    /*
     * Add process id, thread id, and a high resolution timestamp to
     * ensure that the nonce is unique with high probability for
     * different process instances.
     */
    data.pid = now();
    data.tid = 0;
    data.time = get_time_stamp();

    return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}


size_t rand_drbg_get_nonce(RAND_DRBG *drbg,
                           unsigned char **pout,
                           int entropy, size_t min_len, size_t max_len)
{
    size_t ret = 0;
    RAND_POOL *pool;

    struct {
        void * instance;
        int count;
    } data = { 0 };

    pool = rand_pool_new(0, min_len, max_len);
    if (pool == NULL)
        return 0;

    if (rand_pool_add_nonce_data(pool) == 0)
        goto err;

    data.instance = drbg;
    CRYPTO_atomic_add(&rand_nonce_count, 1, &data.count, rand_nonce_lock);

    if (rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0) == 0)
        goto err;

    ret   = rand_pool_length(pool);
    *pout = rand_pool_detach(pool);

    err:
    rand_pool_free(pool);

    return ret;
}

# define MASTER_RESEED_INTERVAL                  (1 << 8)
# define SLAVE_RESEED_INTERVAL                   (1 << 16)
# define MASTER_RESEED_TIME_INTERVAL             (60*60)   /* 1 hour */
# define SLAVE_RESEED_TIME_INTERVAL              (7*60)    /* 7 minutes */
static unsigned int master_reseed_interval = MASTER_RESEED_INTERVAL;
static unsigned int slave_reseed_interval  = SLAVE_RESEED_INTERVAL;

static time_t master_reseed_time_interval = MASTER_RESEED_TIME_INTERVAL;
static time_t slave_reseed_time_interval  = SLAVE_RESEED_TIME_INTERVAL;


#define RAND_DRBG_TYPE_MASTER                     0
#define RAND_DRBG_TYPE_PUBLIC                     1
#define RAND_DRBG_TYPE_PRIVATE                    2


#define SN_aes_128_ctr          "AES-128-CTR"
#define LN_aes_128_ctr          "aes-128-ctr"
#define NID_aes_128_ctr         904

#define SN_aes_192_ctr          "AES-192-CTR"
#define LN_aes_192_ctr          "aes-192-ctr"
#define NID_aes_192_ctr         905

#define SN_aes_256_ctr          "AES-256-CTR"
#define LN_aes_256_ctr          "aes-256-ctr"
#define NID_aes_256_ctr         906

# define RAND_DRBG_STRENGTH             256
/* Default drbg type */
# define RAND_DRBG_TYPE                 NID_aes_256_ctr
/* Default drbg flags */
# define RAND_DRBG_FLAGS                0





# define RAND_DRBG_FLAG_CTR_NO_DF            0x1
# define RAND_DRBG_FLAG_HMAC                 0x2
# define RAND_DRBG_FLAG_MASTER               0x4
# define RAND_DRBG_FLAG_PUBLIC               0x8
# define RAND_DRBG_FLAG_PRIVATE              0x10

static int rand_drbg_type[3] = {
        RAND_DRBG_TYPE, /* Master */
        RAND_DRBG_TYPE, /* Public */
        RAND_DRBG_TYPE  /* Private */
};
static unsigned int rand_drbg_flags[3] = {
        RAND_DRBG_FLAGS | RAND_DRBG_FLAG_MASTER, /* Master */
        RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC, /* Public */
        RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIVATE /* Private */
};


static int is_digest(int type)
{
eosio_assert(false,(char *)"is_digest");
return 1;
}



#define SN_aes_256_ecb          "AES-256-ECB"
#define LN_aes_256_ecb          "aes-256-ecb"
#define NID_aes_256_ecb         426
#define OBJ_aes_256_ecb         OBJ_aes,41L
# define         EVP_CIPH_ECB_MODE               0x1
# define         EVP_CIPH_CBC_MODE               0x2
# define AESNI_CAPABLE   (1<<(57-32))

typedef struct aes_key_st AES_KEY;

# define AES_MAXNR 14
struct aes_key_st {
# ifdef AES_LONG
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
# else
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
# endif
    int rounds;
};


typedef void (*block128_f) (const unsigned char in[16],
                            unsigned char out[16], const void *key);

typedef void (*cbc128_f) (const unsigned char *in, unsigned char *out,
                          size_t len, const void *key,
                          unsigned char ivec[16], int enc);

typedef void (*ctr128_f) (const unsigned char *in, unsigned char *out,
                          size_t blocks, const void *key,
                          const unsigned char ivec[16]);

typedef struct {
    union {
        double align;
        AES_KEY ks;
    } ks;
    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;
} EVP_AES_KEY;

void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher_data;
}

#define EVP_C_DATA(kstruct, ctx) \
        ((kstruct *)EVP_CIPHER_CTX_get_cipher_data(ctx))



unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher)
{
    return cipher->flags;
}

int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx)
{
    return ctx->key_len;
}

const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher;
}

# define AES_ENCRYPT     1
# define AES_DECRYPT     0
# define         EVP_CIPH_MODE                   0xF0007
# define EVP_CIPHER_mode(e)              (EVP_CIPHER_flags(e) & EVP_CIPH_MODE)
# define EVP_CIPHER_CTX_mode(c)         EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(c))
typedef unsigned int u32;
typedef unsigned char u8;
#define GETU32(p)   (((u32)(p)[0] << 24) ^ ((u32)(p)[1] << 16) ^ ((u32)(p)[2] <<  8) ^ ((u32)(p)[3]))
#define PUTU32(p,v) ((p)[0] = (u8)((v) >> 24), (p)[1] = (u8)((v) >> 16), (p)[2] = (u8)((v) >>  8), (p)[3] = (u8)(v))
static const u32 rcon[] = {
        0x00000001U, 0x00000002U, 0x00000004U, 0x00000008U,
        0x00000010U, 0x00000020U, 0x00000040U, 0x00000080U,
        0x0000001bU, 0x00000036U, /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};

static const u32 Te0[256] = {
        0xc66363a5U, 0xf87c7c84U, 0xee777799U, 0xf67b7b8dU,
        0xfff2f20dU, 0xd66b6bbdU, 0xde6f6fb1U, 0x91c5c554U,
        0x60303050U, 0x02010103U, 0xce6767a9U, 0x562b2b7dU,
        0xe7fefe19U, 0xb5d7d762U, 0x4dababe6U, 0xec76769aU,
        0x8fcaca45U, 0x1f82829dU, 0x89c9c940U, 0xfa7d7d87U,
        0xeffafa15U, 0xb25959ebU, 0x8e4747c9U, 0xfbf0f00bU,
        0x41adadecU, 0xb3d4d467U, 0x5fa2a2fdU, 0x45afafeaU,
        0x239c9cbfU, 0x53a4a4f7U, 0xe4727296U, 0x9bc0c05bU,
        0x75b7b7c2U, 0xe1fdfd1cU, 0x3d9393aeU, 0x4c26266aU,
        0x6c36365aU, 0x7e3f3f41U, 0xf5f7f702U, 0x83cccc4fU,
        0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
        0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
        0x0804040cU, 0x95c7c752U, 0x46232365U, 0x9dc3c35eU,
        0x30181828U, 0x379696a1U, 0x0a05050fU, 0x2f9a9ab5U,
        0x0e070709U, 0x24121236U, 0x1b80809bU, 0xdfe2e23dU,
        0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
        0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
        0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
        0xa45252f6U, 0x763b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
        0x5229297bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
        0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
        0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bedU,
        0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
        0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
        0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
        0x864343c5U, 0x9a4d4dd7U, 0x66333355U, 0x11858594U,
        0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
        0xa05050f0U, 0x783c3c44U, 0x259f9fbaU, 0x4ba8a8e3U,
        0xa25151f3U, 0x5da3a3feU, 0x804040c0U, 0x058f8f8aU,
        0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f504U,
        0x63bcbcdfU, 0x77b6b6c1U, 0xafdada75U, 0x42212163U,
        0x20101030U, 0xe5ffff1aU, 0xfdf3f30eU, 0xbfd2d26dU,
        0x81cdcd4cU, 0x180c0c14U, 0x26131335U, 0xc3ecec2fU,
        0xbe5f5fe1U, 0x359797a2U, 0x884444ccU, 0x2e171739U,
        0x93c4c457U, 0x55a7a7f2U, 0xfc7e7e82U, 0x7a3d3d47U,
        0xc86464acU, 0xba5d5de7U, 0x3219192bU, 0xe6737395U,
        0xc06060a0U, 0x19818198U, 0x9e4f4fd1U, 0xa3dcdc7fU,
        0x44222266U, 0x542a2a7eU, 0x3b9090abU, 0x0b888883U,
        0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3U, 0x2814143cU,
        0xa7dede79U, 0xbc5e5ee2U, 0x160b0b1dU, 0xaddbdb76U,
        0xdbe0e03bU, 0x64323256U, 0x743a3a4eU, 0x140a0a1eU,
        0x924949dbU, 0x0c06060aU, 0x4824246cU, 0xb85c5ce4U,
        0x9fc2c25dU, 0xbdd3d36eU, 0x43acacefU, 0xc46262a6U,
        0x399191a8U, 0x319595a4U, 0xd3e4e437U, 0xf279798bU,
        0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
        0x018d8d8cU, 0xb1d5d564U, 0x9c4e4ed2U, 0x49a9a9e0U,
        0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
        0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
        0x6fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2e72U,
        0x381c1c24U, 0x57a6a6f1U, 0x73b4b4c7U, 0x97c6c651U,
        0xcbe8e823U, 0xa1dddd7cU, 0xe874749cU, 0x3e1f1f21U,
        0x964b4bddU, 0x61bdbddcU, 0x0d8b8b86U, 0x0f8a8a85U,
        0xe0707090U, 0x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
        0x904848d8U, 0x06030305U, 0xf7f6f601U, 0x1c0e0e12U,
        0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
        0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
        0xd9e1e138U, 0xebf8f813U, 0x2b9898b3U, 0x22111133U,
        0xd26969bbU, 0xa9d9d970U, 0x078e8e89U, 0x339494a7U,
        0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
        0x87cece49U, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
        0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
        0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd06868b8U,
        0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
        0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU,
};
static const u32 Te1[256] = {
        0xa5c66363U, 0x84f87c7cU, 0x99ee7777U, 0x8df67b7bU,
        0x0dfff2f2U, 0xbdd66b6bU, 0xb1de6f6fU, 0x5491c5c5U,
        0x50603030U, 0x03020101U, 0xa9ce6767U, 0x7d562b2bU,
        0x19e7fefeU, 0x62b5d7d7U, 0xe64dababU, 0x9aec7676U,
        0x458fcacaU, 0x9d1f8282U, 0x4089c9c9U, 0x87fa7d7dU,
        0x15effafaU, 0xebb25959U, 0xc98e4747U, 0x0bfbf0f0U,
        0xec41adadU, 0x67b3d4d4U, 0xfd5fa2a2U, 0xea45afafU,
        0xbf239c9cU, 0xf753a4a4U, 0x96e47272U, 0x5b9bc0c0U,
        0xc275b7b7U, 0x1ce1fdfdU, 0xae3d9393U, 0x6a4c2626U,
        0x5a6c3636U, 0x417e3f3fU, 0x02f5f7f7U, 0x4f83ccccU,
        0x5c683434U, 0xf451a5a5U, 0x34d1e5e5U, 0x08f9f1f1U,
        0x93e27171U, 0x73abd8d8U, 0x53623131U, 0x3f2a1515U,
        0x0c080404U, 0x5295c7c7U, 0x65462323U, 0x5e9dc3c3U,
        0x28301818U, 0xa1379696U, 0x0f0a0505U, 0xb52f9a9aU,
        0x090e0707U, 0x36241212U, 0x9b1b8080U, 0x3ddfe2e2U,
        0x26cdebebU, 0x694e2727U, 0xcd7fb2b2U, 0x9fea7575U,
        0x1b120909U, 0x9e1d8383U, 0x74582c2cU, 0x2e341a1aU,
        0x2d361b1bU, 0xb2dc6e6eU, 0xeeb45a5aU, 0xfb5ba0a0U,
        0xf6a45252U, 0x4d763b3bU, 0x61b7d6d6U, 0xce7db3b3U,
        0x7b522929U, 0x3edde3e3U, 0x715e2f2fU, 0x97138484U,
        0xf5a65353U, 0x68b9d1d1U, 0x00000000U, 0x2cc1ededU,
        0x60402020U, 0x1fe3fcfcU, 0xc879b1b1U, 0xedb65b5bU,
        0xbed46a6aU, 0x468dcbcbU, 0xd967bebeU, 0x4b723939U,
        0xde944a4aU, 0xd4984c4cU, 0xe8b05858U, 0x4a85cfcfU,
        0x6bbbd0d0U, 0x2ac5efefU, 0xe54faaaaU, 0x16edfbfbU,
        0xc5864343U, 0xd79a4d4dU, 0x55663333U, 0x94118585U,
        0xcf8a4545U, 0x10e9f9f9U, 0x06040202U, 0x81fe7f7fU,
        0xf0a05050U, 0x44783c3cU, 0xba259f9fU, 0xe34ba8a8U,
        0xf3a25151U, 0xfe5da3a3U, 0xc0804040U, 0x8a058f8fU,
        0xad3f9292U, 0xbc219d9dU, 0x48703838U, 0x04f1f5f5U,
        0xdf63bcbcU, 0xc177b6b6U, 0x75afdadaU, 0x63422121U,
        0x30201010U, 0x1ae5ffffU, 0x0efdf3f3U, 0x6dbfd2d2U,
        0x4c81cdcdU, 0x14180c0cU, 0x35261313U, 0x2fc3ececU,
        0xe1be5f5fU, 0xa2359797U, 0xcc884444U, 0x392e1717U,
        0x5793c4c4U, 0xf255a7a7U, 0x82fc7e7eU, 0x477a3d3dU,
        0xacc86464U, 0xe7ba5d5dU, 0x2b321919U, 0x95e67373U,
        0xa0c06060U, 0x98198181U, 0xd19e4f4fU, 0x7fa3dcdcU,
        0x66442222U, 0x7e542a2aU, 0xab3b9090U, 0x830b8888U,
        0xca8c4646U, 0x29c7eeeeU, 0xd36bb8b8U, 0x3c281414U,
        0x79a7dedeU, 0xe2bc5e5eU, 0x1d160b0bU, 0x76addbdbU,
        0x3bdbe0e0U, 0x56643232U, 0x4e743a3aU, 0x1e140a0aU,
        0xdb924949U, 0x0a0c0606U, 0x6c482424U, 0xe4b85c5cU,
        0x5d9fc2c2U, 0x6ebdd3d3U, 0xef43acacU, 0xa6c46262U,
        0xa8399191U, 0xa4319595U, 0x37d3e4e4U, 0x8bf27979U,
        0x32d5e7e7U, 0x438bc8c8U, 0x596e3737U, 0xb7da6d6dU,
        0x8c018d8dU, 0x64b1d5d5U, 0xd29c4e4eU, 0xe049a9a9U,
        0xb4d86c6cU, 0xfaac5656U, 0x07f3f4f4U, 0x25cfeaeaU,
        0xafca6565U, 0x8ef47a7aU, 0xe947aeaeU, 0x18100808U,
        0xd56fbabaU, 0x88f07878U, 0x6f4a2525U, 0x725c2e2eU,
        0x24381c1cU, 0xf157a6a6U, 0xc773b4b4U, 0x5197c6c6U,
        0x23cbe8e8U, 0x7ca1ddddU, 0x9ce87474U, 0x213e1f1fU,
        0xdd964b4bU, 0xdc61bdbdU, 0x860d8b8bU, 0x850f8a8aU,
        0x90e07070U, 0x427c3e3eU, 0xc471b5b5U, 0xaacc6666U,
        0xd8904848U, 0x05060303U, 0x01f7f6f6U, 0x121c0e0eU,
        0xa3c26161U, 0x5f6a3535U, 0xf9ae5757U, 0xd069b9b9U,
        0x91178686U, 0x5899c1c1U, 0x273a1d1dU, 0xb9279e9eU,
        0x38d9e1e1U, 0x13ebf8f8U, 0xb32b9898U, 0x33221111U,
        0xbbd26969U, 0x70a9d9d9U, 0x89078e8eU, 0xa7339494U,
        0xb62d9b9bU, 0x223c1e1eU, 0x92158787U, 0x20c9e9e9U,
        0x4987ceceU, 0xffaa5555U, 0x78502828U, 0x7aa5dfdfU,
        0x8f038c8cU, 0xf859a1a1U, 0x80098989U, 0x171a0d0dU,
        0xda65bfbfU, 0x31d7e6e6U, 0xc6844242U, 0xb8d06868U,
        0xc3824141U, 0xb0299999U, 0x775a2d2dU, 0x111e0f0fU,
        0xcb7bb0b0U, 0xfca85454U, 0xd66dbbbbU, 0x3a2c1616U,
};
static const u32 Te2[256] = {
        0x63a5c663U, 0x7c84f87cU, 0x7799ee77U, 0x7b8df67bU,
        0xf20dfff2U, 0x6bbdd66bU, 0x6fb1de6fU, 0xc55491c5U,
        0x30506030U, 0x01030201U, 0x67a9ce67U, 0x2b7d562bU,
        0xfe19e7feU, 0xd762b5d7U, 0xabe64dabU, 0x769aec76U,
        0xca458fcaU, 0x829d1f82U, 0xc94089c9U, 0x7d87fa7dU,
        0xfa15effaU, 0x59ebb259U, 0x47c98e47U, 0xf00bfbf0U,
        0xadec41adU, 0xd467b3d4U, 0xa2fd5fa2U, 0xafea45afU,
        0x9cbf239cU, 0xa4f753a4U, 0x7296e472U, 0xc05b9bc0U,
        0xb7c275b7U, 0xfd1ce1fdU, 0x93ae3d93U, 0x266a4c26U,
        0x365a6c36U, 0x3f417e3fU, 0xf702f5f7U, 0xcc4f83ccU,
        0x345c6834U, 0xa5f451a5U, 0xe534d1e5U, 0xf108f9f1U,
        0x7193e271U, 0xd873abd8U, 0x31536231U, 0x153f2a15U,
        0x040c0804U, 0xc75295c7U, 0x23654623U, 0xc35e9dc3U,
        0x18283018U, 0x96a13796U, 0x050f0a05U, 0x9ab52f9aU,
        0x07090e07U, 0x12362412U, 0x809b1b80U, 0xe23ddfe2U,
        0xeb26cdebU, 0x27694e27U, 0xb2cd7fb2U, 0x759fea75U,
        0x091b1209U, 0x839e1d83U, 0x2c74582cU, 0x1a2e341aU,
        0x1b2d361bU, 0x6eb2dc6eU, 0x5aeeb45aU, 0xa0fb5ba0U,
        0x52f6a452U, 0x3b4d763bU, 0xd661b7d6U, 0xb3ce7db3U,
        0x297b5229U, 0xe33edde3U, 0x2f715e2fU, 0x84971384U,
        0x53f5a653U, 0xd168b9d1U, 0x00000000U, 0xed2cc1edU,
        0x20604020U, 0xfc1fe3fcU, 0xb1c879b1U, 0x5bedb65bU,
        0x6abed46aU, 0xcb468dcbU, 0xbed967beU, 0x394b7239U,
        0x4ade944aU, 0x4cd4984cU, 0x58e8b058U, 0xcf4a85cfU,
        0xd06bbbd0U, 0xef2ac5efU, 0xaae54faaU, 0xfb16edfbU,
        0x43c58643U, 0x4dd79a4dU, 0x33556633U, 0x85941185U,
        0x45cf8a45U, 0xf910e9f9U, 0x02060402U, 0x7f81fe7fU,
        0x50f0a050U, 0x3c44783cU, 0x9fba259fU, 0xa8e34ba8U,
        0x51f3a251U, 0xa3fe5da3U, 0x40c08040U, 0x8f8a058fU,
        0x92ad3f92U, 0x9dbc219dU, 0x38487038U, 0xf504f1f5U,
        0xbcdf63bcU, 0xb6c177b6U, 0xda75afdaU, 0x21634221U,
        0x10302010U, 0xff1ae5ffU, 0xf30efdf3U, 0xd26dbfd2U,
        0xcd4c81cdU, 0x0c14180cU, 0x13352613U, 0xec2fc3ecU,
        0x5fe1be5fU, 0x97a23597U, 0x44cc8844U, 0x17392e17U,
        0xc45793c4U, 0xa7f255a7U, 0x7e82fc7eU, 0x3d477a3dU,
        0x64acc864U, 0x5de7ba5dU, 0x192b3219U, 0x7395e673U,
        0x60a0c060U, 0x81981981U, 0x4fd19e4fU, 0xdc7fa3dcU,
        0x22664422U, 0x2a7e542aU, 0x90ab3b90U, 0x88830b88U,
        0x46ca8c46U, 0xee29c7eeU, 0xb8d36bb8U, 0x143c2814U,
        0xde79a7deU, 0x5ee2bc5eU, 0x0b1d160bU, 0xdb76addbU,
        0xe03bdbe0U, 0x32566432U, 0x3a4e743aU, 0x0a1e140aU,
        0x49db9249U, 0x060a0c06U, 0x246c4824U, 0x5ce4b85cU,
        0xc25d9fc2U, 0xd36ebdd3U, 0xacef43acU, 0x62a6c462U,
        0x91a83991U, 0x95a43195U, 0xe437d3e4U, 0x798bf279U,
        0xe732d5e7U, 0xc8438bc8U, 0x37596e37U, 0x6db7da6dU,
        0x8d8c018dU, 0xd564b1d5U, 0x4ed29c4eU, 0xa9e049a9U,
        0x6cb4d86cU, 0x56faac56U, 0xf407f3f4U, 0xea25cfeaU,
        0x65afca65U, 0x7a8ef47aU, 0xaee947aeU, 0x08181008U,
        0xbad56fbaU, 0x7888f078U, 0x256f4a25U, 0x2e725c2eU,
        0x1c24381cU, 0xa6f157a6U, 0xb4c773b4U, 0xc65197c6U,
        0xe823cbe8U, 0xdd7ca1ddU, 0x749ce874U, 0x1f213e1fU,
        0x4bdd964bU, 0xbddc61bdU, 0x8b860d8bU, 0x8a850f8aU,
        0x7090e070U, 0x3e427c3eU, 0xb5c471b5U, 0x66aacc66U,
        0x48d89048U, 0x03050603U, 0xf601f7f6U, 0x0e121c0eU,
        0x61a3c261U, 0x355f6a35U, 0x57f9ae57U, 0xb9d069b9U,
        0x86911786U, 0xc15899c1U, 0x1d273a1dU, 0x9eb9279eU,
        0xe138d9e1U, 0xf813ebf8U, 0x98b32b98U, 0x11332211U,
        0x69bbd269U, 0xd970a9d9U, 0x8e89078eU, 0x94a73394U,
        0x9bb62d9bU, 0x1e223c1eU, 0x87921587U, 0xe920c9e9U,
        0xce4987ceU, 0x55ffaa55U, 0x28785028U, 0xdf7aa5dfU,
        0x8c8f038cU, 0xa1f859a1U, 0x89800989U, 0x0d171a0dU,
        0xbfda65bfU, 0xe631d7e6U, 0x42c68442U, 0x68b8d068U,
        0x41c38241U, 0x99b02999U, 0x2d775a2dU, 0x0f111e0fU,
        0xb0cb7bb0U, 0x54fca854U, 0xbbd66dbbU, 0x163a2c16U,
};
static const u32 Te3[256] = {
        0x6363a5c6U, 0x7c7c84f8U, 0x777799eeU, 0x7b7b8df6U,
        0xf2f20dffU, 0x6b6bbdd6U, 0x6f6fb1deU, 0xc5c55491U,
        0x30305060U, 0x01010302U, 0x6767a9ceU, 0x2b2b7d56U,
        0xfefe19e7U, 0xd7d762b5U, 0xababe64dU, 0x76769aecU,
        0xcaca458fU, 0x82829d1fU, 0xc9c94089U, 0x7d7d87faU,
        0xfafa15efU, 0x5959ebb2U, 0x4747c98eU, 0xf0f00bfbU,
        0xadadec41U, 0xd4d467b3U, 0xa2a2fd5fU, 0xafafea45U,
        0x9c9cbf23U, 0xa4a4f753U, 0x727296e4U, 0xc0c05b9bU,
        0xb7b7c275U, 0xfdfd1ce1U, 0x9393ae3dU, 0x26266a4cU,
        0x36365a6cU, 0x3f3f417eU, 0xf7f702f5U, 0xcccc4f83U,
        0x34345c68U, 0xa5a5f451U, 0xe5e534d1U, 0xf1f108f9U,
        0x717193e2U, 0xd8d873abU, 0x31315362U, 0x15153f2aU,
        0x04040c08U, 0xc7c75295U, 0x23236546U, 0xc3c35e9dU,
        0x18182830U, 0x9696a137U, 0x05050f0aU, 0x9a9ab52fU,
        0x0707090eU, 0x12123624U, 0x80809b1bU, 0xe2e23ddfU,
        0xebeb26cdU, 0x2727694eU, 0xb2b2cd7fU, 0x75759feaU,
        0x09091b12U, 0x83839e1dU, 0x2c2c7458U, 0x1a1a2e34U,
        0x1b1b2d36U, 0x6e6eb2dcU, 0x5a5aeeb4U, 0xa0a0fb5bU,
        0x5252f6a4U, 0x3b3b4d76U, 0xd6d661b7U, 0xb3b3ce7dU,
        0x29297b52U, 0xe3e33eddU, 0x2f2f715eU, 0x84849713U,
        0x5353f5a6U, 0xd1d168b9U, 0x00000000U, 0xeded2cc1U,
        0x20206040U, 0xfcfc1fe3U, 0xb1b1c879U, 0x5b5bedb6U,
        0x6a6abed4U, 0xcbcb468dU, 0xbebed967U, 0x39394b72U,
        0x4a4ade94U, 0x4c4cd498U, 0x5858e8b0U, 0xcfcf4a85U,
        0xd0d06bbbU, 0xefef2ac5U, 0xaaaae54fU, 0xfbfb16edU,
        0x4343c586U, 0x4d4dd79aU, 0x33335566U, 0x85859411U,
        0x4545cf8aU, 0xf9f910e9U, 0x02020604U, 0x7f7f81feU,
        0x5050f0a0U, 0x3c3c4478U, 0x9f9fba25U, 0xa8a8e34bU,
        0x5151f3a2U, 0xa3a3fe5dU, 0x4040c080U, 0x8f8f8a05U,
        0x9292ad3fU, 0x9d9dbc21U, 0x38384870U, 0xf5f504f1U,
        0xbcbcdf63U, 0xb6b6c177U, 0xdada75afU, 0x21216342U,
        0x10103020U, 0xffff1ae5U, 0xf3f30efdU, 0xd2d26dbfU,
        0xcdcd4c81U, 0x0c0c1418U, 0x13133526U, 0xecec2fc3U,
        0x5f5fe1beU, 0x9797a235U, 0x4444cc88U, 0x1717392eU,
        0xc4c45793U, 0xa7a7f255U, 0x7e7e82fcU, 0x3d3d477aU,
        0x6464acc8U, 0x5d5de7baU, 0x19192b32U, 0x737395e6U,
        0x6060a0c0U, 0x81819819U, 0x4f4fd19eU, 0xdcdc7fa3U,
        0x22226644U, 0x2a2a7e54U, 0x9090ab3bU, 0x8888830bU,
        0x4646ca8cU, 0xeeee29c7U, 0xb8b8d36bU, 0x14143c28U,
        0xdede79a7U, 0x5e5ee2bcU, 0x0b0b1d16U, 0xdbdb76adU,
        0xe0e03bdbU, 0x32325664U, 0x3a3a4e74U, 0x0a0a1e14U,
        0x4949db92U, 0x06060a0cU, 0x24246c48U, 0x5c5ce4b8U,
        0xc2c25d9fU, 0xd3d36ebdU, 0xacacef43U, 0x6262a6c4U,
        0x9191a839U, 0x9595a431U, 0xe4e437d3U, 0x79798bf2U,
        0xe7e732d5U, 0xc8c8438bU, 0x3737596eU, 0x6d6db7daU,
        0x8d8d8c01U, 0xd5d564b1U, 0x4e4ed29cU, 0xa9a9e049U,
        0x6c6cb4d8U, 0x5656faacU, 0xf4f407f3U, 0xeaea25cfU,
        0x6565afcaU, 0x7a7a8ef4U, 0xaeaee947U, 0x08081810U,
        0xbabad56fU, 0x787888f0U, 0x25256f4aU, 0x2e2e725cU,
        0x1c1c2438U, 0xa6a6f157U, 0xb4b4c773U, 0xc6c65197U,
        0xe8e823cbU, 0xdddd7ca1U, 0x74749ce8U, 0x1f1f213eU,
        0x4b4bdd96U, 0xbdbddc61U, 0x8b8b860dU, 0x8a8a850fU,
        0x707090e0U, 0x3e3e427cU, 0xb5b5c471U, 0x6666aaccU,
        0x4848d890U, 0x03030506U, 0xf6f601f7U, 0x0e0e121cU,
        0x6161a3c2U, 0x35355f6aU, 0x5757f9aeU, 0xb9b9d069U,
        0x86869117U, 0xc1c15899U, 0x1d1d273aU, 0x9e9eb927U,
        0xe1e138d9U, 0xf8f813ebU, 0x9898b32bU, 0x11113322U,
        0x6969bbd2U, 0xd9d970a9U, 0x8e8e8907U, 0x9494a733U,
        0x9b9bb62dU, 0x1e1e223cU, 0x87879215U, 0xe9e920c9U,
        0xcece4987U, 0x5555ffaaU, 0x28287850U, 0xdfdf7aa5U,
        0x8c8c8f03U, 0xa1a1f859U, 0x89898009U, 0x0d0d171aU,
        0xbfbfda65U, 0xe6e631d7U, 0x4242c684U, 0x6868b8d0U,
        0x4141c382U, 0x9999b029U, 0x2d2d775aU, 0x0f0f111eU,
        0xb0b0cb7bU, 0x5454fca8U, 0xbbbbd66dU, 0x16163a2cU,
};

static const u32 Td0[256] = {
        0x51f4a750U, 0x7e416553U, 0x1a17a4c3U, 0x3a275e96U,
        0x3bab6bcbU, 0x1f9d45f1U, 0xacfa58abU, 0x4be30393U,
        0x2030fa55U, 0xad766df6U, 0x88cc7691U, 0xf5024c25U,
        0x4fe5d7fcU, 0xc52acbd7U, 0x26354480U, 0xb562a38fU,
        0xdeb15a49U, 0x25ba1b67U, 0x45ea0e98U, 0x5dfec0e1U,
        0xc32f7502U, 0x814cf012U, 0x8d4697a3U, 0x6bd3f9c6U,
        0x038f5fe7U, 0x15929c95U, 0xbf6d7aebU, 0x955259daU,
        0xd4be832dU, 0x587421d3U, 0x49e06929U, 0x8ec9c844U,
        0x75c2896aU, 0xf48e7978U, 0x99583e6bU, 0x27b971ddU,
        0xbee14fb6U, 0xf088ad17U, 0xc920ac66U, 0x7dce3ab4U,
        0x63df4a18U, 0xe51a3182U, 0x97513360U, 0x62537f45U,
        0xb16477e0U, 0xbb6bae84U, 0xfe81a01cU, 0xf9082b94U,
        0x70486858U, 0x8f45fd19U, 0x94de6c87U, 0x527bf8b7U,
        0xab73d323U, 0x724b02e2U, 0xe31f8f57U, 0x6655ab2aU,
        0xb2eb2807U, 0x2fb5c203U, 0x86c57b9aU, 0xd33708a5U,
        0x302887f2U, 0x23bfa5b2U, 0x02036abaU, 0xed16825cU,
        0x8acf1c2bU, 0xa779b492U, 0xf307f2f0U, 0x4e69e2a1U,
        0x65daf4cdU, 0x0605bed5U, 0xd134621fU, 0xc4a6fe8aU,
        0x342e539dU, 0xa2f355a0U, 0x058ae132U, 0xa4f6eb75U,
        0x0b83ec39U, 0x4060efaaU, 0x5e719f06U, 0xbd6e1051U,
        0x3e218af9U, 0x96dd063dU, 0xdd3e05aeU, 0x4de6bd46U,
        0x91548db5U, 0x71c45d05U, 0x0406d46fU, 0x605015ffU,
        0x1998fb24U, 0xd6bde997U, 0x894043ccU, 0x67d99e77U,
        0xb0e842bdU, 0x07898b88U, 0xe7195b38U, 0x79c8eedbU,
        0xa17c0a47U, 0x7c420fe9U, 0xf8841ec9U, 0x00000000U,
        0x09808683U, 0x322bed48U, 0x1e1170acU, 0x6c5a724eU,
        0xfd0efffbU, 0x0f853856U, 0x3daed51eU, 0x362d3927U,
        0x0a0fd964U, 0x685ca621U, 0x9b5b54d1U, 0x24362e3aU,
        0x0c0a67b1U, 0x9357e70fU, 0xb4ee96d2U, 0x1b9b919eU,
        0x80c0c54fU, 0x61dc20a2U, 0x5a774b69U, 0x1c121a16U,
        0xe293ba0aU, 0xc0a02ae5U, 0x3c22e043U, 0x121b171dU,
        0x0e090d0bU, 0xf28bc7adU, 0x2db6a8b9U, 0x141ea9c8U,
        0x57f11985U, 0xaf75074cU, 0xee99ddbbU, 0xa37f60fdU,
        0xf701269fU, 0x5c72f5bcU, 0x44663bc5U, 0x5bfb7e34U,
        0x8b432976U, 0xcb23c6dcU, 0xb6edfc68U, 0xb8e4f163U,
        0xd731dccaU, 0x42638510U, 0x13972240U, 0x84c61120U,
        0x854a247dU, 0xd2bb3df8U, 0xaef93211U, 0xc729a16dU,
        0x1d9e2f4bU, 0xdcb230f3U, 0x0d8652ecU, 0x77c1e3d0U,
        0x2bb3166cU, 0xa970b999U, 0x119448faU, 0x47e96422U,
        0xa8fc8cc4U, 0xa0f03f1aU, 0x567d2cd8U, 0x223390efU,
        0x87494ec7U, 0xd938d1c1U, 0x8ccaa2feU, 0x98d40b36U,
        0xa6f581cfU, 0xa57ade28U, 0xdab78e26U, 0x3fadbfa4U,
        0x2c3a9de4U, 0x5078920dU, 0x6a5fcc9bU, 0x547e4662U,
        0xf68d13c2U, 0x90d8b8e8U, 0x2e39f75eU, 0x82c3aff5U,
        0x9f5d80beU, 0x69d0937cU, 0x6fd52da9U, 0xcf2512b3U,
        0xc8ac993bU, 0x10187da7U, 0xe89c636eU, 0xdb3bbb7bU,
        0xcd267809U, 0x6e5918f4U, 0xec9ab701U, 0x834f9aa8U,
        0xe6956e65U, 0xaaffe67eU, 0x21bccf08U, 0xef15e8e6U,
        0xbae79bd9U, 0x4a6f36ceU, 0xea9f09d4U, 0x29b07cd6U,
        0x31a4b2afU, 0x2a3f2331U, 0xc6a59430U, 0x35a266c0U,
        0x744ebc37U, 0xfc82caa6U, 0xe090d0b0U, 0x33a7d815U,
        0xf104984aU, 0x41ecdaf7U, 0x7fcd500eU, 0x1791f62fU,
        0x764dd68dU, 0x43efb04dU, 0xccaa4d54U, 0xe49604dfU,
        0x9ed1b5e3U, 0x4c6a881bU, 0xc12c1fb8U, 0x4665517fU,
        0x9d5eea04U, 0x018c355dU, 0xfa877473U, 0xfb0b412eU,
        0xb3671d5aU, 0x92dbd252U, 0xe9105633U, 0x6dd64713U,
        0x9ad7618cU, 0x37a10c7aU, 0x59f8148eU, 0xeb133c89U,
        0xcea927eeU, 0xb761c935U, 0xe11ce5edU, 0x7a47b13cU,
        0x9cd2df59U, 0x55f2733fU, 0x1814ce79U, 0x73c737bfU,
        0x53f7cdeaU, 0x5ffdaa5bU, 0xdf3d6f14U, 0x7844db86U,
        0xcaaff381U, 0xb968c43eU, 0x3824342cU, 0xc2a3405fU,
        0x161dc372U, 0xbce2250cU, 0x283c498bU, 0xff0d9541U,
        0x39a80171U, 0x080cb3deU, 0xd8b4e49cU, 0x6456c190U,
        0x7bcb8461U, 0xd532b670U, 0x486c5c74U, 0xd0b85742U,
};
static const u32 Td1[256] = {
        0x5051f4a7U, 0x537e4165U, 0xc31a17a4U, 0x963a275eU,
        0xcb3bab6bU, 0xf11f9d45U, 0xabacfa58U, 0x934be303U,
        0x552030faU, 0xf6ad766dU, 0x9188cc76U, 0x25f5024cU,
        0xfc4fe5d7U, 0xd7c52acbU, 0x80263544U, 0x8fb562a3U,
        0x49deb15aU, 0x6725ba1bU, 0x9845ea0eU, 0xe15dfec0U,
        0x02c32f75U, 0x12814cf0U, 0xa38d4697U, 0xc66bd3f9U,
        0xe7038f5fU, 0x9515929cU, 0xebbf6d7aU, 0xda955259U,
        0x2dd4be83U, 0xd3587421U, 0x2949e069U, 0x448ec9c8U,
        0x6a75c289U, 0x78f48e79U, 0x6b99583eU, 0xdd27b971U,
        0xb6bee14fU, 0x17f088adU, 0x66c920acU, 0xb47dce3aU,
        0x1863df4aU, 0x82e51a31U, 0x60975133U, 0x4562537fU,
        0xe0b16477U, 0x84bb6baeU, 0x1cfe81a0U, 0x94f9082bU,
        0x58704868U, 0x198f45fdU, 0x8794de6cU, 0xb7527bf8U,
        0x23ab73d3U, 0xe2724b02U, 0x57e31f8fU, 0x2a6655abU,
        0x07b2eb28U, 0x032fb5c2U, 0x9a86c57bU, 0xa5d33708U,
        0xf2302887U, 0xb223bfa5U, 0xba02036aU, 0x5ced1682U,
        0x2b8acf1cU, 0x92a779b4U, 0xf0f307f2U, 0xa14e69e2U,
        0xcd65daf4U, 0xd50605beU, 0x1fd13462U, 0x8ac4a6feU,
        0x9d342e53U, 0xa0a2f355U, 0x32058ae1U, 0x75a4f6ebU,
        0x390b83ecU, 0xaa4060efU, 0x065e719fU, 0x51bd6e10U,
        0xf93e218aU, 0x3d96dd06U, 0xaedd3e05U, 0x464de6bdU,
        0xb591548dU, 0x0571c45dU, 0x6f0406d4U, 0xff605015U,
        0x241998fbU, 0x97d6bde9U, 0xcc894043U, 0x7767d99eU,
        0xbdb0e842U, 0x8807898bU, 0x38e7195bU, 0xdb79c8eeU,
        0x47a17c0aU, 0xe97c420fU, 0xc9f8841eU, 0x00000000U,
        0x83098086U, 0x48322bedU, 0xac1e1170U, 0x4e6c5a72U,
        0xfbfd0effU, 0x560f8538U, 0x1e3daed5U, 0x27362d39U,
        0x640a0fd9U, 0x21685ca6U, 0xd19b5b54U, 0x3a24362eU,
        0xb10c0a67U, 0x0f9357e7U, 0xd2b4ee96U, 0x9e1b9b91U,
        0x4f80c0c5U, 0xa261dc20U, 0x695a774bU, 0x161c121aU,
        0x0ae293baU, 0xe5c0a02aU, 0x433c22e0U, 0x1d121b17U,
        0x0b0e090dU, 0xadf28bc7U, 0xb92db6a8U, 0xc8141ea9U,
        0x8557f119U, 0x4caf7507U, 0xbbee99ddU, 0xfda37f60U,
        0x9ff70126U, 0xbc5c72f5U, 0xc544663bU, 0x345bfb7eU,
        0x768b4329U, 0xdccb23c6U, 0x68b6edfcU, 0x63b8e4f1U,
        0xcad731dcU, 0x10426385U, 0x40139722U, 0x2084c611U,
        0x7d854a24U, 0xf8d2bb3dU, 0x11aef932U, 0x6dc729a1U,
        0x4b1d9e2fU, 0xf3dcb230U, 0xec0d8652U, 0xd077c1e3U,
        0x6c2bb316U, 0x99a970b9U, 0xfa119448U, 0x2247e964U,
        0xc4a8fc8cU, 0x1aa0f03fU, 0xd8567d2cU, 0xef223390U,
        0xc787494eU, 0xc1d938d1U, 0xfe8ccaa2U, 0x3698d40bU,
        0xcfa6f581U, 0x28a57adeU, 0x26dab78eU, 0xa43fadbfU,
        0xe42c3a9dU, 0x0d507892U, 0x9b6a5fccU, 0x62547e46U,
        0xc2f68d13U, 0xe890d8b8U, 0x5e2e39f7U, 0xf582c3afU,
        0xbe9f5d80U, 0x7c69d093U, 0xa96fd52dU, 0xb3cf2512U,
        0x3bc8ac99U, 0xa710187dU, 0x6ee89c63U, 0x7bdb3bbbU,
        0x09cd2678U, 0xf46e5918U, 0x01ec9ab7U, 0xa8834f9aU,
        0x65e6956eU, 0x7eaaffe6U, 0x0821bccfU, 0xe6ef15e8U,
        0xd9bae79bU, 0xce4a6f36U, 0xd4ea9f09U, 0xd629b07cU,
        0xaf31a4b2U, 0x312a3f23U, 0x30c6a594U, 0xc035a266U,
        0x37744ebcU, 0xa6fc82caU, 0xb0e090d0U, 0x1533a7d8U,
        0x4af10498U, 0xf741ecdaU, 0x0e7fcd50U, 0x2f1791f6U,
        0x8d764dd6U, 0x4d43efb0U, 0x54ccaa4dU, 0xdfe49604U,
        0xe39ed1b5U, 0x1b4c6a88U, 0xb8c12c1fU, 0x7f466551U,
        0x049d5eeaU, 0x5d018c35U, 0x73fa8774U, 0x2efb0b41U,
        0x5ab3671dU, 0x5292dbd2U, 0x33e91056U, 0x136dd647U,
        0x8c9ad761U, 0x7a37a10cU, 0x8e59f814U, 0x89eb133cU,
        0xeecea927U, 0x35b761c9U, 0xede11ce5U, 0x3c7a47b1U,
        0x599cd2dfU, 0x3f55f273U, 0x791814ceU, 0xbf73c737U,
        0xea53f7cdU, 0x5b5ffdaaU, 0x14df3d6fU, 0x867844dbU,
        0x81caaff3U, 0x3eb968c4U, 0x2c382434U, 0x5fc2a340U,
        0x72161dc3U, 0x0cbce225U, 0x8b283c49U, 0x41ff0d95U,
        0x7139a801U, 0xde080cb3U, 0x9cd8b4e4U, 0x906456c1U,
        0x617bcb84U, 0x70d532b6U, 0x74486c5cU, 0x42d0b857U,
};
static const u32 Td2[256] = {
        0xa75051f4U, 0x65537e41U, 0xa4c31a17U, 0x5e963a27U,
        0x6bcb3babU, 0x45f11f9dU, 0x58abacfaU, 0x03934be3U,
        0xfa552030U, 0x6df6ad76U, 0x769188ccU, 0x4c25f502U,
        0xd7fc4fe5U, 0xcbd7c52aU, 0x44802635U, 0xa38fb562U,
        0x5a49deb1U, 0x1b6725baU, 0x0e9845eaU, 0xc0e15dfeU,
        0x7502c32fU, 0xf012814cU, 0x97a38d46U, 0xf9c66bd3U,
        0x5fe7038fU, 0x9c951592U, 0x7aebbf6dU, 0x59da9552U,
        0x832dd4beU, 0x21d35874U, 0x692949e0U, 0xc8448ec9U,
        0x896a75c2U, 0x7978f48eU, 0x3e6b9958U, 0x71dd27b9U,
        0x4fb6bee1U, 0xad17f088U, 0xac66c920U, 0x3ab47dceU,
        0x4a1863dfU, 0x3182e51aU, 0x33609751U, 0x7f456253U,
        0x77e0b164U, 0xae84bb6bU, 0xa01cfe81U, 0x2b94f908U,
        0x68587048U, 0xfd198f45U, 0x6c8794deU, 0xf8b7527bU,
        0xd323ab73U, 0x02e2724bU, 0x8f57e31fU, 0xab2a6655U,
        0x2807b2ebU, 0xc2032fb5U, 0x7b9a86c5U, 0x08a5d337U,
        0x87f23028U, 0xa5b223bfU, 0x6aba0203U, 0x825ced16U,
        0x1c2b8acfU, 0xb492a779U, 0xf2f0f307U, 0xe2a14e69U,
        0xf4cd65daU, 0xbed50605U, 0x621fd134U, 0xfe8ac4a6U,
        0x539d342eU, 0x55a0a2f3U, 0xe132058aU, 0xeb75a4f6U,
        0xec390b83U, 0xefaa4060U, 0x9f065e71U, 0x1051bd6eU,
        0x8af93e21U, 0x063d96ddU, 0x05aedd3eU, 0xbd464de6U,
        0x8db59154U, 0x5d0571c4U, 0xd46f0406U, 0x15ff6050U,
        0xfb241998U, 0xe997d6bdU, 0x43cc8940U, 0x9e7767d9U,
        0x42bdb0e8U, 0x8b880789U, 0x5b38e719U, 0xeedb79c8U,
        0x0a47a17cU, 0x0fe97c42U, 0x1ec9f884U, 0x00000000U,
        0x86830980U, 0xed48322bU, 0x70ac1e11U, 0x724e6c5aU,
        0xfffbfd0eU, 0x38560f85U, 0xd51e3daeU, 0x3927362dU,
        0xd9640a0fU, 0xa621685cU, 0x54d19b5bU, 0x2e3a2436U,
        0x67b10c0aU, 0xe70f9357U, 0x96d2b4eeU, 0x919e1b9bU,
        0xc54f80c0U, 0x20a261dcU, 0x4b695a77U, 0x1a161c12U,
        0xba0ae293U, 0x2ae5c0a0U, 0xe0433c22U, 0x171d121bU,
        0x0d0b0e09U, 0xc7adf28bU, 0xa8b92db6U, 0xa9c8141eU,
        0x198557f1U, 0x074caf75U, 0xddbbee99U, 0x60fda37fU,
        0x269ff701U, 0xf5bc5c72U, 0x3bc54466U, 0x7e345bfbU,
        0x29768b43U, 0xc6dccb23U, 0xfc68b6edU, 0xf163b8e4U,
        0xdccad731U, 0x85104263U, 0x22401397U, 0x112084c6U,
        0x247d854aU, 0x3df8d2bbU, 0x3211aef9U, 0xa16dc729U,
        0x2f4b1d9eU, 0x30f3dcb2U, 0x52ec0d86U, 0xe3d077c1U,
        0x166c2bb3U, 0xb999a970U, 0x48fa1194U, 0x642247e9U,
        0x8cc4a8fcU, 0x3f1aa0f0U, 0x2cd8567dU, 0x90ef2233U,
        0x4ec78749U, 0xd1c1d938U, 0xa2fe8ccaU, 0x0b3698d4U,
        0x81cfa6f5U, 0xde28a57aU, 0x8e26dab7U, 0xbfa43fadU,
        0x9de42c3aU, 0x920d5078U, 0xcc9b6a5fU, 0x4662547eU,
        0x13c2f68dU, 0xb8e890d8U, 0xf75e2e39U, 0xaff582c3U,
        0x80be9f5dU, 0x937c69d0U, 0x2da96fd5U, 0x12b3cf25U,
        0x993bc8acU, 0x7da71018U, 0x636ee89cU, 0xbb7bdb3bU,
        0x7809cd26U, 0x18f46e59U, 0xb701ec9aU, 0x9aa8834fU,
        0x6e65e695U, 0xe67eaaffU, 0xcf0821bcU, 0xe8e6ef15U,
        0x9bd9bae7U, 0x36ce4a6fU, 0x09d4ea9fU, 0x7cd629b0U,
        0xb2af31a4U, 0x23312a3fU, 0x9430c6a5U, 0x66c035a2U,
        0xbc37744eU, 0xcaa6fc82U, 0xd0b0e090U, 0xd81533a7U,
        0x984af104U, 0xdaf741ecU, 0x500e7fcdU, 0xf62f1791U,
        0xd68d764dU, 0xb04d43efU, 0x4d54ccaaU, 0x04dfe496U,
        0xb5e39ed1U, 0x881b4c6aU, 0x1fb8c12cU, 0x517f4665U,
        0xea049d5eU, 0x355d018cU, 0x7473fa87U, 0x412efb0bU,
        0x1d5ab367U, 0xd25292dbU, 0x5633e910U, 0x47136dd6U,
        0x618c9ad7U, 0x0c7a37a1U, 0x148e59f8U, 0x3c89eb13U,
        0x27eecea9U, 0xc935b761U, 0xe5ede11cU, 0xb13c7a47U,
        0xdf599cd2U, 0x733f55f2U, 0xce791814U, 0x37bf73c7U,
        0xcdea53f7U, 0xaa5b5ffdU, 0x6f14df3dU, 0xdb867844U,
        0xf381caafU, 0xc43eb968U, 0x342c3824U, 0x405fc2a3U,
        0xc372161dU, 0x250cbce2U, 0x498b283cU, 0x9541ff0dU,
        0x017139a8U, 0xb3de080cU, 0xe49cd8b4U, 0xc1906456U,
        0x84617bcbU, 0xb670d532U, 0x5c74486cU, 0x5742d0b8U,
};
static const u32 Td3[256] = {
        0xf4a75051U, 0x4165537eU, 0x17a4c31aU, 0x275e963aU,
        0xab6bcb3bU, 0x9d45f11fU, 0xfa58abacU, 0xe303934bU,
        0x30fa5520U, 0x766df6adU, 0xcc769188U, 0x024c25f5U,
        0xe5d7fc4fU, 0x2acbd7c5U, 0x35448026U, 0x62a38fb5U,
        0xb15a49deU, 0xba1b6725U, 0xea0e9845U, 0xfec0e15dU,
        0x2f7502c3U, 0x4cf01281U, 0x4697a38dU, 0xd3f9c66bU,
        0x8f5fe703U, 0x929c9515U, 0x6d7aebbfU, 0x5259da95U,
        0xbe832dd4U, 0x7421d358U, 0xe0692949U, 0xc9c8448eU,
        0xc2896a75U, 0x8e7978f4U, 0x583e6b99U, 0xb971dd27U,
        0xe14fb6beU, 0x88ad17f0U, 0x20ac66c9U, 0xce3ab47dU,
        0xdf4a1863U, 0x1a3182e5U, 0x51336097U, 0x537f4562U,
        0x6477e0b1U, 0x6bae84bbU, 0x81a01cfeU, 0x082b94f9U,
        0x48685870U, 0x45fd198fU, 0xde6c8794U, 0x7bf8b752U,
        0x73d323abU, 0x4b02e272U, 0x1f8f57e3U, 0x55ab2a66U,
        0xeb2807b2U, 0xb5c2032fU, 0xc57b9a86U, 0x3708a5d3U,
        0x2887f230U, 0xbfa5b223U, 0x036aba02U, 0x16825cedU,
        0xcf1c2b8aU, 0x79b492a7U, 0x07f2f0f3U, 0x69e2a14eU,
        0xdaf4cd65U, 0x05bed506U, 0x34621fd1U, 0xa6fe8ac4U,
        0x2e539d34U, 0xf355a0a2U, 0x8ae13205U, 0xf6eb75a4U,
        0x83ec390bU, 0x60efaa40U, 0x719f065eU, 0x6e1051bdU,
        0x218af93eU, 0xdd063d96U, 0x3e05aeddU, 0xe6bd464dU,
        0x548db591U, 0xc45d0571U, 0x06d46f04U, 0x5015ff60U,
        0x98fb2419U, 0xbde997d6U, 0x4043cc89U, 0xd99e7767U,
        0xe842bdb0U, 0x898b8807U, 0x195b38e7U, 0xc8eedb79U,
        0x7c0a47a1U, 0x420fe97cU, 0x841ec9f8U, 0x00000000U,
        0x80868309U, 0x2bed4832U, 0x1170ac1eU, 0x5a724e6cU,
        0x0efffbfdU, 0x8538560fU, 0xaed51e3dU, 0x2d392736U,
        0x0fd9640aU, 0x5ca62168U, 0x5b54d19bU, 0x362e3a24U,
        0x0a67b10cU, 0x57e70f93U, 0xee96d2b4U, 0x9b919e1bU,
        0xc0c54f80U, 0xdc20a261U, 0x774b695aU, 0x121a161cU,
        0x93ba0ae2U, 0xa02ae5c0U, 0x22e0433cU, 0x1b171d12U,
        0x090d0b0eU, 0x8bc7adf2U, 0xb6a8b92dU, 0x1ea9c814U,
        0xf1198557U, 0x75074cafU, 0x99ddbbeeU, 0x7f60fda3U,
        0x01269ff7U, 0x72f5bc5cU, 0x663bc544U, 0xfb7e345bU,
        0x4329768bU, 0x23c6dccbU, 0xedfc68b6U, 0xe4f163b8U,
        0x31dccad7U, 0x63851042U, 0x97224013U, 0xc6112084U,
        0x4a247d85U, 0xbb3df8d2U, 0xf93211aeU, 0x29a16dc7U,
        0x9e2f4b1dU, 0xb230f3dcU, 0x8652ec0dU, 0xc1e3d077U,
        0xb3166c2bU, 0x70b999a9U, 0x9448fa11U, 0xe9642247U,
        0xfc8cc4a8U, 0xf03f1aa0U, 0x7d2cd856U, 0x3390ef22U,
        0x494ec787U, 0x38d1c1d9U, 0xcaa2fe8cU, 0xd40b3698U,
        0xf581cfa6U, 0x7ade28a5U, 0xb78e26daU, 0xadbfa43fU,
        0x3a9de42cU, 0x78920d50U, 0x5fcc9b6aU, 0x7e466254U,
        0x8d13c2f6U, 0xd8b8e890U, 0x39f75e2eU, 0xc3aff582U,
        0x5d80be9fU, 0xd0937c69U, 0xd52da96fU, 0x2512b3cfU,
        0xac993bc8U, 0x187da710U, 0x9c636ee8U, 0x3bbb7bdbU,
        0x267809cdU, 0x5918f46eU, 0x9ab701ecU, 0x4f9aa883U,
        0x956e65e6U, 0xffe67eaaU, 0xbccf0821U, 0x15e8e6efU,
        0xe79bd9baU, 0x6f36ce4aU, 0x9f09d4eaU, 0xb07cd629U,
        0xa4b2af31U, 0x3f23312aU, 0xa59430c6U, 0xa266c035U,
        0x4ebc3774U, 0x82caa6fcU, 0x90d0b0e0U, 0xa7d81533U,
        0x04984af1U, 0xecdaf741U, 0xcd500e7fU, 0x91f62f17U,
        0x4dd68d76U, 0xefb04d43U, 0xaa4d54ccU, 0x9604dfe4U,
        0xd1b5e39eU, 0x6a881b4cU, 0x2c1fb8c1U, 0x65517f46U,
        0x5eea049dU, 0x8c355d01U, 0x877473faU, 0x0b412efbU,
        0x671d5ab3U, 0xdbd25292U, 0x105633e9U, 0xd647136dU,
        0xd7618c9aU, 0xa10c7a37U, 0xf8148e59U, 0x133c89ebU,
        0xa927eeceU, 0x61c935b7U, 0x1ce5ede1U, 0x47b13c7aU,
        0xd2df599cU, 0xf2733f55U, 0x14ce7918U, 0xc737bf73U,
        0xf7cdea53U, 0xfdaa5b5fU, 0x3d6f14dfU, 0x44db8678U,
        0xaff381caU, 0x68c43eb9U, 0x24342c38U, 0xa3405fc2U,
        0x1dc37216U, 0xe2250cbcU, 0x3c498b28U, 0x0d9541ffU,
        0xa8017139U, 0x0cb3de08U, 0xb4e49cd8U, 0x56c19064U,
        0xcb84617bU, 0x32b670d5U, 0x6c5c7448U, 0xb85742d0U,
};
static const u8 Td4[256] = {
        0x52U, 0x09U, 0x6aU, 0xd5U, 0x30U, 0x36U, 0xa5U, 0x38U,
        0xbfU, 0x40U, 0xa3U, 0x9eU, 0x81U, 0xf3U, 0xd7U, 0xfbU,
        0x7cU, 0xe3U, 0x39U, 0x82U, 0x9bU, 0x2fU, 0xffU, 0x87U,
        0x34U, 0x8eU, 0x43U, 0x44U, 0xc4U, 0xdeU, 0xe9U, 0xcbU,
        0x54U, 0x7bU, 0x94U, 0x32U, 0xa6U, 0xc2U, 0x23U, 0x3dU,
        0xeeU, 0x4cU, 0x95U, 0x0bU, 0x42U, 0xfaU, 0xc3U, 0x4eU,
        0x08U, 0x2eU, 0xa1U, 0x66U, 0x28U, 0xd9U, 0x24U, 0xb2U,
        0x76U, 0x5bU, 0xa2U, 0x49U, 0x6dU, 0x8bU, 0xd1U, 0x25U,
        0x72U, 0xf8U, 0xf6U, 0x64U, 0x86U, 0x68U, 0x98U, 0x16U,
        0xd4U, 0xa4U, 0x5cU, 0xccU, 0x5dU, 0x65U, 0xb6U, 0x92U,
        0x6cU, 0x70U, 0x48U, 0x50U, 0xfdU, 0xedU, 0xb9U, 0xdaU,
        0x5eU, 0x15U, 0x46U, 0x57U, 0xa7U, 0x8dU, 0x9dU, 0x84U,
        0x90U, 0xd8U, 0xabU, 0x00U, 0x8cU, 0xbcU, 0xd3U, 0x0aU,
        0xf7U, 0xe4U, 0x58U, 0x05U, 0xb8U, 0xb3U, 0x45U, 0x06U,
        0xd0U, 0x2cU, 0x1eU, 0x8fU, 0xcaU, 0x3fU, 0x0fU, 0x02U,
        0xc1U, 0xafU, 0xbdU, 0x03U, 0x01U, 0x13U, 0x8aU, 0x6bU,
        0x3aU, 0x91U, 0x11U, 0x41U, 0x4fU, 0x67U, 0xdcU, 0xeaU,
        0x97U, 0xf2U, 0xcfU, 0xceU, 0xf0U, 0xb4U, 0xe6U, 0x73U,
        0x96U, 0xacU, 0x74U, 0x22U, 0xe7U, 0xadU, 0x35U, 0x85U,
        0xe2U, 0xf9U, 0x37U, 0xe8U, 0x1cU, 0x75U, 0xdfU, 0x6eU,
        0x47U, 0xf1U, 0x1aU, 0x71U, 0x1dU, 0x29U, 0xc5U, 0x89U,
        0x6fU, 0xb7U, 0x62U, 0x0eU, 0xaaU, 0x18U, 0xbeU, 0x1bU,
        0xfcU, 0x56U, 0x3eU, 0x4bU, 0xc6U, 0xd2U, 0x79U, 0x20U,
        0x9aU, 0xdbU, 0xc0U, 0xfeU, 0x78U, 0xcdU, 0x5aU, 0xf4U,
        0x1fU, 0xddU, 0xa8U, 0x33U, 0x88U, 0x07U, 0xc7U, 0x31U,
        0xb1U, 0x12U, 0x10U, 0x59U, 0x27U, 0x80U, 0xecU, 0x5fU,
        0x60U, 0x51U, 0x7fU, 0xa9U, 0x19U, 0xb5U, 0x4aU, 0x0dU,
        0x2dU, 0xe5U, 0x7aU, 0x9fU, 0x93U, 0xc9U, 0x9cU, 0xefU,
        0xa0U, 0xe0U, 0x3bU, 0x4dU, 0xaeU, 0x2aU, 0xf5U, 0xb0U,
        0xc8U, 0xebU, 0xbbU, 0x3cU, 0x83U, 0x53U, 0x99U, 0x61U,
        0x17U, 0x2bU, 0x04U, 0x7eU, 0xbaU, 0x77U, 0xd6U, 0x26U,
        0xe1U, 0x69U, 0x14U, 0x63U, 0x55U, 0x21U, 0x0cU, 0x7dU,
};

static const u8 Te4[256] = {
        0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U,
        0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U,
        0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U,
        0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U,
        0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU,
        0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U,
        0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU,
        0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U,
        0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U,
        0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U,
        0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU,
        0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU,
        0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U,
        0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U,
        0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U,
        0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U,
        0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U,
        0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U,
        0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U,
        0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU,
        0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU,
        0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U,
        0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U,
        0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U,
        0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U,
        0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU,
        0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU,
        0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU,
        0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U,
        0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU,
        0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U,
        0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U
};


int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key)
{

    u32 *rk;
    int i = 0;
    u32 temp;

    if (!userKey || !key)
        return -1;
    if (bits != 128 && bits != 192 && bits != 256)
        return -2;

    rk = key->rd_key;

    if (bits==128)
        key->rounds = 10;
    else if (bits==192)
        key->rounds = 12;
    else
        key->rounds = 14;

    rk[0] = GETU32(userKey     );
    rk[1] = GETU32(userKey +  4);
    rk[2] = GETU32(userKey +  8);
    rk[3] = GETU32(userKey + 12);
    if (bits == 128) {
        while (1) {
            temp  = rk[3];
            rk[4] = rk[0] ^
                    ((u32)Te4[(temp >>  8) & 0xff]      ) ^
                    ((u32)Te4[(temp >> 16) & 0xff] <<  8) ^
                    ((u32)Te4[(temp >> 24)       ] << 16) ^
                    ((u32)Te4[(temp      ) & 0xff] << 24) ^
                    rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) {
                return 0;
            }
            rk += 4;
        }
    }
    rk[4] = GETU32(userKey + 16);
    rk[5] = GETU32(userKey + 20);
    if (bits == 192) {
        while (1) {
            temp = rk[ 5];
            rk[ 6] = rk[ 0] ^
                     ((u32)Te4[(temp >>  8) & 0xff]      ) ^
                     ((u32)Te4[(temp >> 16) & 0xff] <<  8) ^
                     ((u32)Te4[(temp >> 24)       ] << 16) ^
                     ((u32)Te4[(temp      ) & 0xff] << 24) ^
                     rcon[i];
            rk[ 7] = rk[ 1] ^ rk[ 6];
            rk[ 8] = rk[ 2] ^ rk[ 7];
            rk[ 9] = rk[ 3] ^ rk[ 8];
            if (++i == 8) {
                return 0;
            }
            rk[10] = rk[ 4] ^ rk[ 9];
            rk[11] = rk[ 5] ^ rk[10];
            rk += 6;
        }
    }
    rk[6] = GETU32(userKey + 24);
    rk[7] = GETU32(userKey + 28);
    if (bits == 256) {
        while (1) {
            temp = rk[ 7];
            rk[ 8] = rk[ 0] ^
                     ((u32)Te4[(temp >>  8) & 0xff]      ) ^
                     ((u32)Te4[(temp >> 16) & 0xff] <<  8) ^
                     ((u32)Te4[(temp >> 24)       ] << 16) ^
                     ((u32)Te4[(temp      ) & 0xff] << 24) ^
                     rcon[i];
            rk[ 9] = rk[ 1] ^ rk[ 8];
            rk[10] = rk[ 2] ^ rk[ 9];
            rk[11] = rk[ 3] ^ rk[10];
            if (++i == 7) {
                return 0;
            }
            temp = rk[11];
            rk[12] = rk[ 4] ^
                     ((u32)Te4[(temp      ) & 0xff]      ) ^
                     ((u32)Te4[(temp >>  8) & 0xff] <<  8) ^
                     ((u32)Te4[(temp >> 16) & 0xff] << 16) ^
                     ((u32)Te4[(temp >> 24)       ] << 24);
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];

            rk += 8;
        }
    }
    return 0;
}

int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key)
{

    u32 *rk;
    int i, j, status;
    u32 temp;

    /* first, start with an encryption schedule */
    status = AES_set_encrypt_key(userKey, bits, key);
    if (status < 0)
        return status;

    rk = key->rd_key;

    /* invert the order of the round keys: */
    for (i = 0, j = 4*(key->rounds); i < j; i += 4, j -= 4) {
        temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
        temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
        temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
        temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
    }
    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    for (i = 1; i < (key->rounds); i++) {
        rk += 4;
#if 1
        for (j = 0; j < 4; j++) {
            u32 tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

            tp1 = rk[j];
            m = tp1 & 0x80808080;
            tp2 = ((tp1 & 0x7f7f7f7f) << 1) ^
                  ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp2 & 0x80808080;
            tp4 = ((tp2 & 0x7f7f7f7f) << 1) ^
                  ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp4 & 0x80808080;
            tp8 = ((tp4 & 0x7f7f7f7f) << 1) ^
                  ((m - (m >> 7)) & 0x1b1b1b1b);
            tp9 = tp8 ^ tp1;
            tpb = tp9 ^ tp2;
            tpd = tp9 ^ tp4;
            tpe = tp8 ^ tp4 ^ tp2;
#if defined(ROTATE)
            rk[j] = tpe ^ ROTATE(tpd,16) ^
                ROTATE(tp9,8) ^ ROTATE(tpb,24);
#else
            rk[j] = tpe ^ (tpd >> 16) ^ (tpd << 16) ^
                    (tp9 >> 24) ^ (tp9 << 8) ^
                    (tpb >> 8) ^ (tpb << 24);
#endif
        }
#else
        rk[0] =
            Td0[Te2[(rk[0]      ) & 0xff] & 0xff] ^
            Td1[Te2[(rk[0] >>  8) & 0xff] & 0xff] ^
            Td2[Te2[(rk[0] >> 16) & 0xff] & 0xff] ^
            Td3[Te2[(rk[0] >> 24)       ] & 0xff];
        rk[1] =
            Td0[Te2[(rk[1]      ) & 0xff] & 0xff] ^
            Td1[Te2[(rk[1] >>  8) & 0xff] & 0xff] ^
            Td2[Te2[(rk[1] >> 16) & 0xff] & 0xff] ^
            Td3[Te2[(rk[1] >> 24)       ] & 0xff];
        rk[2] =
            Td0[Te2[(rk[2]      ) & 0xff] & 0xff] ^
            Td1[Te2[(rk[2] >>  8) & 0xff] & 0xff] ^
            Td2[Te2[(rk[2] >> 16) & 0xff] & 0xff] ^
            Td3[Te2[(rk[2] >> 24)       ] & 0xff];
        rk[3] =
            Td0[Te2[(rk[3]      ) & 0xff] & 0xff] ^
            Td1[Te2[(rk[3] >>  8) & 0xff] & 0xff] ^
            Td2[Te2[(rk[3] >> 16) & 0xff] & 0xff] ^
            Td3[Te2[(rk[3] >> 24)       ] & 0xff];
#endif
    }
    return 0;
}

static int aesni_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                          const unsigned char *iv, int enc)
{
    int ret, mode;
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    mode = EVP_CIPHER_CTX_mode(ctx);
    if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE)
        && !enc) {
        eosio_assert(false, (char *)"aesni_init_key enc");
    } else {
        ret = 1;
        ret = AES_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                    &dat->ks.ks);
        dat->stream.cbc = NULL;
    }

    if (ret < 0) {
        eosio_assert(false, (char *)"EVP_F_AESNI_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED");
        return 0;
    }

    return 1;
}

# define         EVP_CIPH_FLAG_DEFAULT_ASN1      0x1000

int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->block_size;
}


/*
 * Encrypt a single block
 * in and out can overlap
 */
void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key) {

    const u32 *rk;
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
#ifndef FULL_UNROLL
    int r;
#endif /* ?FULL_UNROLL */

    assert(in && out && key);
    rk = key->rd_key;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(in     ) ^ rk[0];
    s1 = GETU32(in +  4) ^ rk[1];
    s2 = GETU32(in +  8) ^ rk[2];
    s3 = GETU32(in + 12) ^ rk[3];
#ifdef FULL_UNROLL
    /* round 1: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[ 4];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[ 5];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[ 6];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[ 7];
    /* round 2: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[ 8];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[ 9];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
    /* round 3: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
    /* round 4: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
    /* round 5: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];
    /* round 6: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];
    /* round 7: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];
    /* round 8: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
    /* round 9: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
    if (key->rounds > 10) {
        /* round 10: */
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[40];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[41];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[42];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[43];
        /* round 11: */
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[44];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[45];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[46];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[47];
        if (key->rounds > 12) {
            /* round 12: */
            s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[48];
            s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[49];
            s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[50];
            s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[51];
            /* round 13: */
            t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[52];
            t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[53];
            t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[54];
            t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[55];
        }
    }
    rk += key->rounds << 2;
#else  /* !FULL_UNROLL */
    /*
     * Nr - 1 full rounds:
     */
    r = key->rounds >> 1;
    for (;;) {
        t0 =
                Te0[(s0 >> 24)       ] ^
                Te1[(s1 >> 16) & 0xff] ^
                Te2[(s2 >>  8) & 0xff] ^
                Te3[(s3      ) & 0xff] ^
                rk[4];
        t1 =
                Te0[(s1 >> 24)       ] ^
                Te1[(s2 >> 16) & 0xff] ^
                Te2[(s3 >>  8) & 0xff] ^
                Te3[(s0      ) & 0xff] ^
                rk[5];
        t2 =
                Te0[(s2 >> 24)       ] ^
                Te1[(s3 >> 16) & 0xff] ^
                Te2[(s0 >>  8) & 0xff] ^
                Te3[(s1      ) & 0xff] ^
                rk[6];
        t3 =
                Te0[(s3 >> 24)       ] ^
                Te1[(s0 >> 16) & 0xff] ^
                Te2[(s1 >>  8) & 0xff] ^
                Te3[(s2      ) & 0xff] ^
                rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        s0 =
                Te0[(t0 >> 24)       ] ^
                Te1[(t1 >> 16) & 0xff] ^
                Te2[(t2 >>  8) & 0xff] ^
                Te3[(t3      ) & 0xff] ^
                rk[0];
        s1 =
                Te0[(t1 >> 24)       ] ^
                Te1[(t2 >> 16) & 0xff] ^
                Te2[(t3 >>  8) & 0xff] ^
                Te3[(t0      ) & 0xff] ^
                rk[1];
        s2 =
                Te0[(t2 >> 24)       ] ^
                Te1[(t3 >> 16) & 0xff] ^
                Te2[(t0 >>  8) & 0xff] ^
                Te3[(t1      ) & 0xff] ^
                rk[2];
        s3 =
                Te0[(t3 >> 24)       ] ^
                Te1[(t0 >> 16) & 0xff] ^
                Te2[(t1 >>  8) & 0xff] ^
                Te3[(t2      ) & 0xff] ^
                rk[3];
    }
#endif /* ?FULL_UNROLL */
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
            (Te2[(t0 >> 24)       ] & 0xff000000) ^
            (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
            (Te0[(t2 >>  8) & 0xff] & 0x0000ff00) ^
            (Te1[(t3      ) & 0xff] & 0x000000ff) ^
            rk[0];
    PUTU32(out,s0);
    s1 =
            (Te2[(t1 >> 24)       ] & 0xff000000) ^
            (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
            (Te0[(t3 >>  8) & 0xff] & 0x0000ff00) ^
            (Te1[(t0      ) & 0xff] & 0x000000ff) ^
            rk[1];
    PUTU32(out +  4, s1);
    s2 =
            (Te2[(t2 >> 24)       ] & 0xff000000) ^
            (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
            (Te0[(t0 >>  8) & 0xff] & 0x0000ff00) ^
            (Te1[(t1      ) & 0xff] & 0x000000ff) ^
            rk[2];
    PUTU32(out +  8, s2);
    s3 =
            (Te2[(t3 >> 24)       ] & 0xff000000) ^
            (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
            (Te0[(t1 >>  8) & 0xff] & 0x0000ff00) ^
            (Te1[(t2      ) & 0xff] & 0x000000ff) ^
            rk[3];
    PUTU32(out + 12, s3);
}

/*
 * Decrypt a single block
 * in and out can overlap
 */
void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key)
{

    const u32 *rk;
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
#ifndef FULL_UNROLL
    int r;
#endif /* ?FULL_UNROLL */

    assert(in && out && key);
    rk = key->rd_key;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(in     ) ^ rk[0];
    s1 = GETU32(in +  4) ^ rk[1];
    s2 = GETU32(in +  8) ^ rk[2];
    s3 = GETU32(in + 12) ^ rk[3];
#ifdef FULL_UNROLL
    /* round 1: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[ 4];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[ 5];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[ 6];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[ 7];
    /* round 2: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[ 8];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[ 9];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[10];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[11];
    /* round 3: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[12];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[13];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[14];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[15];
    /* round 4: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[16];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[17];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[18];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[19];
    /* round 5: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[20];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[21];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[22];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[23];
    /* round 6: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[24];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[25];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[26];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[27];
    /* round 7: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[28];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[29];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[30];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[31];
    /* round 8: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[32];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[33];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[34];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[35];
    /* round 9: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[36];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[37];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[38];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[39];
    if (key->rounds > 10) {
        /* round 10: */
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[40];
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[41];
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[42];
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[43];
        /* round 11: */
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[44];
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[45];
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[46];
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[47];
        if (key->rounds > 12) {
            /* round 12: */
            s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[48];
            s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[49];
            s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[50];
            s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[51];
            /* round 13: */
            t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[52];
            t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[53];
            t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[54];
            t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[55];
        }
    }
    rk += key->rounds << 2;
#else  /* !FULL_UNROLL */
    /*
     * Nr - 1 full rounds:
     */
    r = key->rounds >> 1;
    for (;;) {
        t0 =
                Td0[(s0 >> 24)       ] ^
                Td1[(s3 >> 16) & 0xff] ^
                Td2[(s2 >>  8) & 0xff] ^
                Td3[(s1      ) & 0xff] ^
                rk[4];
        t1 =
                Td0[(s1 >> 24)       ] ^
                Td1[(s0 >> 16) & 0xff] ^
                Td2[(s3 >>  8) & 0xff] ^
                Td3[(s2      ) & 0xff] ^
                rk[5];
        t2 =
                Td0[(s2 >> 24)       ] ^
                Td1[(s1 >> 16) & 0xff] ^
                Td2[(s0 >>  8) & 0xff] ^
                Td3[(s3      ) & 0xff] ^
                rk[6];
        t3 =
                Td0[(s3 >> 24)       ] ^
                Td1[(s2 >> 16) & 0xff] ^
                Td2[(s1 >>  8) & 0xff] ^
                Td3[(s0      ) & 0xff] ^
                rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        s0 =
                Td0[(t0 >> 24)       ] ^
                Td1[(t3 >> 16) & 0xff] ^
                Td2[(t2 >>  8) & 0xff] ^
                Td3[(t1      ) & 0xff] ^
                rk[0];
        s1 =
                Td0[(t1 >> 24)       ] ^
                Td1[(t0 >> 16) & 0xff] ^
                Td2[(t3 >>  8) & 0xff] ^
                Td3[(t2      ) & 0xff] ^
                rk[1];
        s2 =
                Td0[(t2 >> 24)       ] ^
                Td1[(t1 >> 16) & 0xff] ^
                Td2[(t0 >>  8) & 0xff] ^
                Td3[(t3      ) & 0xff] ^
                rk[2];
        s3 =
                Td0[(t3 >> 24)       ] ^
                Td1[(t2 >> 16) & 0xff] ^
                Td2[(t1 >>  8) & 0xff] ^
                Td3[(t0      ) & 0xff] ^
                rk[3];
    }
#endif /* ?FULL_UNROLL */
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
            ((u32)Td4[(t0 >> 24)       ] << 24) ^
            ((u32)Td4[(t3 >> 16) & 0xff] << 16) ^
            ((u32)Td4[(t2 >>  8) & 0xff] <<  8) ^
            ((u32)Td4[(t1      ) & 0xff])       ^
            rk[0];
    PUTU32(out     , s0);
    s1 =
            ((u32)Td4[(t1 >> 24)       ] << 24) ^
            ((u32)Td4[(t0 >> 16) & 0xff] << 16) ^
            ((u32)Td4[(t3 >>  8) & 0xff] <<  8) ^
            ((u32)Td4[(t2      ) & 0xff])       ^
            rk[1];
    PUTU32(out +  4, s1);
    s2 =
            ((u32)Td4[(t2 >> 24)       ] << 24) ^
            ((u32)Td4[(t1 >> 16) & 0xff] << 16) ^
            ((u32)Td4[(t0 >>  8) & 0xff] <<  8) ^
            ((u32)Td4[(t3      ) & 0xff])       ^
            rk[2];
    PUTU32(out +  8, s2);
    s3 =
            ((u32)Td4[(t3 >> 24)       ] << 24) ^
            ((u32)Td4[(t2 >> 16) & 0xff] << 16) ^
            ((u32)Td4[(t1 >>  8) & 0xff] <<  8) ^
            ((u32)Td4[(t0      ) & 0xff])       ^
            rk[3];
    PUTU32(out + 12, s3);
}

void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     const AES_KEY *key, const int enc)
{

    assert(in && out && key);
    assert((AES_ENCRYPT == enc) || (AES_DECRYPT == enc));

    if (AES_ENCRYPT == enc)
        AES_encrypt(in, out, key);
    else
        AES_decrypt(in, out, key);
}


int EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx)
{
    return ctx->encrypt;
}


static int aesni_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t len)
{
    size_t bl = EVP_CIPHER_CTX_block_size(ctx);

    if (len < bl)
        return 1;

    AES_ecb_encrypt(in, out, &EVP_C_DATA(EVP_AES_KEY,ctx)->ks.ks,
                      EVP_CIPHER_CTX_encrypting(ctx));

    return 1;
}



static int aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    size_t bl = EVP_CIPHER_CTX_block_size(ctx);
    size_t i;
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    if (len < bl)
        return 1;

    for (i = 0, len -= bl; i <= len; i += bl)
        (*dat->block) (in + i, out + i, &dat->ks);

    return 1;
}

static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    int ret, mode;
//    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);
//
//    mode = EVP_CIPHER_CTX_mode(ctx);
//    if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE)
//        && !enc) {
//#ifdef HWAES_CAPABLE
//        if (HWAES_CAPABLE) {
//            ret = HWAES_set_decrypt_key(key,
//                                        EVP_CIPHER_CTX_key_length(ctx) * 8,
//                                        &dat->ks.ks);
//            dat->block = (block128_f) HWAES_decrypt;
//            dat->stream.cbc = NULL;
//# ifdef HWAES_cbc_encrypt
//            if (mode == EVP_CIPH_CBC_MODE)
//                dat->stream.cbc = (cbc128_f) HWAES_cbc_encrypt;
//# endif
//        } else
//#endif
//#ifdef BSAES_CAPABLE
//        if (BSAES_CAPABLE && mode == EVP_CIPH_CBC_MODE) {
//            ret = AES_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
//                                      &dat->ks.ks);
//            dat->block = (block128_f) AES_decrypt;
//            dat->stream.cbc = (cbc128_f) bsaes_cbc_encrypt;
//        } else
//#endif
//#ifdef VPAES_CAPABLE
//        if (VPAES_CAPABLE) {
//            ret = vpaes_set_decrypt_key(key,
//                                        EVP_CIPHER_CTX_key_length(ctx) * 8,
//                                        &dat->ks.ks);
//            dat->block = (block128_f) vpaes_decrypt;
//            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
//                (cbc128_f) vpaes_cbc_encrypt : NULL;
//        } else
//#endif
//        {
//            ret = AES_set_decrypt_key(key,
//                                      EVP_CIPHER_CTX_key_length(ctx) * 8,
//                                      &dat->ks.ks);
//            dat->block = (block128_f) AES_decrypt;
//            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
//                              (cbc128_f) AES_cbc_encrypt : NULL;
//        }
//    } else
//#ifdef HWAES_CAPABLE
//        if (HWAES_CAPABLE) {
//        ret = HWAES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
//                                    &dat->ks.ks);
//        dat->block = (block128_f) HWAES_encrypt;
//        dat->stream.cbc = NULL;
//# ifdef HWAES_cbc_encrypt
//        if (mode == EVP_CIPH_CBC_MODE)
//            dat->stream.cbc = (cbc128_f) HWAES_cbc_encrypt;
//        else
//# endif
//# ifdef HWAES_ctr32_encrypt_blocks
//        if (mode == EVP_CIPH_CTR_MODE)
//            dat->stream.ctr = (ctr128_f) HWAES_ctr32_encrypt_blocks;
//        else
//# endif
//            (void)0;            /* terminate potentially open 'else' */
//    } else
//#endif
//#ifdef BSAES_CAPABLE
//        if (BSAES_CAPABLE && mode == EVP_CIPH_CTR_MODE) {
//        ret = AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
//                                  &dat->ks.ks);
//        dat->block = (block128_f) AES_encrypt;
//        dat->stream.ctr = (ctr128_f) bsaes_ctr32_encrypt_blocks;
//    } else
//#endif
//#ifdef VPAES_CAPABLE
//        if (VPAES_CAPABLE) {
//        ret = vpaes_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
//                                    &dat->ks.ks);
//        dat->block = (block128_f) vpaes_encrypt;
//        dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
//            (cbc128_f) vpaes_cbc_encrypt : NULL;
//    } else
//#endif
//    {
//        ret = AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
//                                  &dat->ks.ks);
//        dat->block = (block128_f) AES_encrypt;
//        dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
//                          (cbc128_f) AES_cbc_encrypt : NULL;
//#ifdef AES_CTR_ASM
//        if (mode == EVP_CIPH_CTR_MODE)
//            dat->stream.ctr = (ctr128_f) AES_ctr32_encrypt;
//#endif
//    }
//
//    if (ret < 0) {
//        EVPerr(EVP_F_AES_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED);
//        return 0;
//    }

eosio_assert(false,(char *)"aes_init_key");
    return 1;
}

const EVP_CIPHER *EVP_aes_256_ecb(void);
# define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER aesni_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aesni_init_key,                 \
        aesni_##mode##_cipher,          \
        NULL,                           \
        sizeof(EVP_AES_KEY),            \
        NULL,NULL,NULL,NULL }; \
static const EVP_CIPHER aes_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,     \
        keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aes_init_key,                   \
        aes_##mode##_cipher,            \
        NULL,                           \
        sizeof(EVP_AES_KEY),            \
        NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return AESNI_CAPABLE?&aesni_##keylen##_##mode:&aes_##keylen##_##mode; }


# define BLOCK_CIPHER_generic_pack(nid,keylen,flags)             \
        BLOCK_CIPHER_generic(nid,keylen,16,0,ecb,ecb,ECB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)

BLOCK_CIPHER_generic_pack(NID_aes, 256, 0)


static RAND_DRBG_METHOD drbg_ctr_meth = {
};


int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c)
{
    if (c == NULL)
        return 1;
    if (c->cipher != NULL) {
        if (c->cipher->cleanup && !c->cipher->cleanup(c))
            return 0;
        /* Cleanse cipher context data */
        if (c->cipher_data && c->cipher->ctx_size)
            OPENSSL_cleanse(c->cipher_data, c->cipher->ctx_size);
    }

    CRYPTO_free(c->cipher_data);
    memset(c, 0, sizeof(*c));
    return 1;
}

# define         EVP_CIPHER_CTX_FLAG_WRAP_ALLOW  0x1
# define         EVP_CIPH_CTRL_INIT              0x40
# define         EVP_CTRL_INIT                   0x0


int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    int ret;

    if (!ctx->cipher) {
        eosio_assert(false, (char *)"EVP_F_EVP_CIPHER_CTX_CTRL, EVP_R_NO_CIPHER_SET");
        return 0;
    }

    if (!ctx->cipher->ctrl) {
        eosio_assert(false, (char *)"EVP_F_EVP_CIPHER_CTX_CTRL, EVP_R_CTRL_NOT_IMPLEMENTED");
        return 0;
    }

    ret = ctx->cipher->ctrl(ctx, type, arg, ptr);
    if (ret == -1) {
        eosio_assert(false, (char *)"EVP_F_EVP_CIPHER_CTX_CTRL,EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED");
        return 0;
    }
    return ret;
}


# define         EVP_CIPH_WRAP_MODE              0x10002
# define         EVP_CIPH_OCB_MODE               0x10003
# define         EVP_CIPH_MODE                   0xF0007
# define         EVP_CIPH_CUSTOM_IV              0x10
# define         EVP_CIPH_STREAM_CIPHER          0x0
# define         EVP_CIPH_ECB_MODE               0x1
# define         EVP_CIPH_CFB_MODE               0x3
# define         EVP_CIPH_OFB_MODE               0x4
# define         EVP_CIPH_CTR_MODE               0x5
# define         EVP_CIPH_ALWAYS_CALL_INIT       0x20

int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->iv_len;
}

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                      ENGINE *impl, const unsigned char *key,
                      const unsigned char *iv, int enc)
{
    if (enc == -1)
        enc = ctx->encrypt;
    else {
        if (enc)
            enc = 1;
        ctx->encrypt = enc;
    }

    if (cipher) {
        /*
         * Ensure a context left lying around from last time is cleared (the
         * previous check attempted to avoid this if the same ENGINE and
         * EVP_CIPHER could be used).
         */
        if (ctx->cipher) {
            unsigned long flags = ctx->flags;
            EVP_CIPHER_CTX_reset(ctx);
            /* Restore encrypt and flags */
            ctx->encrypt = enc;
            ctx->flags = flags;
        }

        ctx->cipher = cipher;
        if (ctx->cipher->ctx_size) {
            ctx->cipher_data = CRYPTO_zalloc(ctx->cipher->ctx_size);
            if (ctx->cipher_data == NULL) {
                ctx->cipher = NULL;
                eosio_assert(false, (char *)"EVP_F_EVP_CIPHERINIT_EX, ERR_R_MALLOC_FAILURE");
                return 0;
            }
        } else {
            ctx->cipher_data = NULL;
        }
        ctx->key_len = cipher->key_len;
        /* Preserve wrap enable flag, zero everything else */
        ctx->flags &= EVP_CIPHER_CTX_FLAG_WRAP_ALLOW;
        if (ctx->cipher->flags & EVP_CIPH_CTRL_INIT) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_INIT, 0, NULL)) {
                ctx->cipher = NULL;
                eosio_assert(false, (char *)"EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR");
                return 0;
            }
        }
    } else if (!ctx->cipher) {
        eosio_assert(false, (char *)"EVP_F_EVP_CIPHERINIT_EX, EVP_R_NO_CIPHER_SET");
        return 0;
    }

    /* we assume block size is a power of 2 in *cryptUpdate */
    int block_size = ctx->cipher->block_size;
    if( !(block_size == 1 || block_size == 8 || block_size == 16)){
        eosio_assert(false, (char *)"ctx->cipher->block_size != 1 or 8 or 16");
    }

    if (!(ctx->flags & EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
        && EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_WRAP_MODE) {
        eosio_assert(false, (char *)"EVP_F_EVP_CIPHERINIT_EX, EVP_R_WRAP_MODE_NOT_ALLOWED");
        return 0;
    }

    if (!(EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(ctx)) & EVP_CIPH_CUSTOM_IV)) {
        switch (EVP_CIPHER_CTX_mode(ctx)) {

            case EVP_CIPH_STREAM_CIPHER:
            case EVP_CIPH_ECB_MODE:
                break;

            case EVP_CIPH_CFB_MODE:
            case EVP_CIPH_OFB_MODE:

                ctx->num = 0;
                /* fall-through */

            case EVP_CIPH_CBC_MODE:

                if(EVP_CIPHER_CTX_iv_length(ctx) >
                               (int)sizeof(ctx->iv)){
                    eosio_assert(false, (char *)"VP_CIPHER_CTX_iv_length(ctx)");
                }
                if (iv)
                    memcpy(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
                memcpy(ctx->iv, ctx->oiv, EVP_CIPHER_CTX_iv_length(ctx));
                break;

            case EVP_CIPH_CTR_MODE:
                ctx->num = 0;
                /* Don't reuse IV for CTR mode */
                if (iv)
                    memcpy(ctx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
                break;

            default:
                return 0;
        }
    }

    if (key || (ctx->cipher->flags & EVP_CIPH_ALWAYS_CALL_INIT)) {
        if (!aesni_init_key(ctx, key, iv, enc))
            return 0;
    }
    ctx->buf_len = 0;
    ctx->final_used = 0;
    ctx->block_mask = ctx->cipher->block_size - 1;
    return 1;
}

# define DRBG_MAX_LENGTH                         INT32_MAX
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)
{
    return (EVP_CIPHER_CTX *)CRYPTO_zalloc(sizeof(EVP_CIPHER_CTX));
}
int drbg_ctr_init(RAND_DRBG *drbg)
{
    RAND_DRBG_CTR *ctr = &drbg->data.ctr;
    size_t keylen;

    switch (drbg->type) {
        default:
            /* This can't happen, but silence the compiler warning. */
            return 0;
        case NID_aes_128_ctr:
        case NID_aes_192_ctr:
            eosio_assert(false,(char *)"NID_aes_128_ctr");
            break;
        case NID_aes_256_ctr:
            keylen = 32;
            ctr->cipher = EVP_aes_256_ecb();
            break;
    }

    drbg->meth = &drbg_ctr_meth;

    ctr->keylen = keylen;
    if (ctr->ctx == NULL)
        ctr->ctx = EVP_CIPHER_CTX_new();
    if (ctr->ctx == NULL)
        return 0;
    drbg->strength = keylen * 8;
    drbg->seedlen = keylen + 16;

    if ((drbg->flags & RAND_DRBG_FLAG_CTR_NO_DF) == 0) {
        /* df initialisation */
        static const unsigned char df_key[32] = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        if (ctr->ctx_df == NULL)
            ctr->ctx_df = EVP_CIPHER_CTX_new();
        if (ctr->ctx_df == NULL)
            return 0;
        /* Set key schedule for df_key */
        if (!EVP_CipherInit_ex(ctr->ctx_df, ctr->cipher, NULL, df_key, NULL, 1))
            return 0;

        drbg->min_entropylen = ctr->keylen;
        drbg->max_entropylen = DRBG_MAX_LENGTH;
        drbg->min_noncelen = drbg->min_entropylen / 2;
        drbg->max_noncelen = DRBG_MAX_LENGTH;
        drbg->max_perslen = DRBG_MAX_LENGTH;
        drbg->max_adinlen = DRBG_MAX_LENGTH;
    } else {
        drbg->min_entropylen = drbg->seedlen;
        drbg->max_entropylen = drbg->seedlen;
        /* Nonce not used */
        drbg->min_noncelen = 0;
        drbg->max_noncelen = 0;
        drbg->max_perslen = drbg->seedlen;
        drbg->max_adinlen = drbg->seedlen;
    }

    drbg->max_request = 1 << 16;

    return 1;
}

static int is_ctr(int type) {
    switch (type) {
        case NID_aes_128_ctr:
        case NID_aes_192_ctr:
        case NID_aes_256_ctr:
            return 1;
        default:
            return 0;
    }

}


int RAND_DRBG_set(RAND_DRBG *drbg, int type, unsigned int flags)
{
    int ret = 1;

    if (type == 0 && flags == 0) {
        type = rand_drbg_type[RAND_DRBG_TYPE_MASTER];
        flags = rand_drbg_flags[RAND_DRBG_TYPE_MASTER];
    }

    /* If set is called multiple times - clear the old one */
    if (drbg->type != 0 && (type != drbg->type || flags != drbg->flags)) {
        drbg->meth->uninstantiate(drbg);
        rand_pool_free(drbg->adin_pool);
        drbg->adin_pool = NULL;
    }

    drbg->state = DRBG_UNINITIALISED;
    drbg->flags = flags;
    drbg->type = type;

    if (type == 0) {
        /* Uninitialized; that's okay. */
        drbg->meth = NULL;
        return 1;
    } else if (is_ctr(type)) {
        ret = drbg_ctr_init(drbg);
    }else {
        drbg->type = 0;
        drbg->flags = 0;
        drbg->meth = NULL;
        eosio_assert(false, (char *)"RAND_F_RAND_DRBG_SET, RAND_R_UNSUPPORTED_DRBG_TYPE");
        return 0;
    }

    if (ret == 0) {
        drbg->state = DRBG_ERROR;
        eosio_assert(false, (char *)"RAND_F_RAND_DRBG_SET, RAND_R_ERROR_INITIALISING_DRBG");
    }
    return ret;
}

# define CRYPTO_EX_INDEX_DRBG            15
void RAND_DRBG_free(RAND_DRBG *drbg)
{
    if (drbg == NULL)
        return;

    if (drbg->meth != NULL)
        drbg->meth->uninstantiate(drbg);
    rand_pool_free(drbg->adin_pool);
    CRYPTO_clear_free(drbg, sizeof(*drbg));
}

void rand_drbg_cleanup_nonce(RAND_DRBG *drbg,
                             unsigned char *out, size_t outlen)
{
    CRYPTO_clear_free(out, outlen);
}


static RAND_DRBG *rand_drbg_new(int secure,
                                int type,
                                unsigned int flags,
                                RAND_DRBG *parent)
{
    RAND_DRBG *drbg = (RAND_DRBG *)CRYPTO_zalloc(sizeof(*drbg));

    if (drbg == NULL) {
        eosio_assert(false, (char *)"RAND_F_RAND_DRBG_NEW, ERR_R_MALLOC_FAILURE");
        return NULL;
    }

    drbg->secure = secure;
    drbg->fork_count = rand_fork_count;
    drbg->parent = parent;

    if (parent == NULL) {
        drbg->get_entropy = rand_drbg_get_entropy;
        drbg->cleanup_entropy = rand_drbg_cleanup_entropy;
#ifndef RAND_DRBG_GET_RANDOM_NONCE
        drbg->get_nonce = rand_drbg_get_nonce;
        drbg->cleanup_nonce = rand_drbg_cleanup_nonce;
#endif

        drbg->reseed_interval = master_reseed_interval;
        drbg->reseed_time_interval = master_reseed_time_interval;
    } else {
        drbg->get_entropy = rand_drbg_get_entropy;
        drbg->cleanup_entropy = rand_drbg_cleanup_entropy;
        /*
         * Do not provide nonce callbacks, the child DRBGs will
         * obtain their nonce using random bits from the parent.
         */

        drbg->reseed_interval = slave_reseed_interval;
        drbg->reseed_time_interval = slave_reseed_time_interval;
    }

    if (RAND_DRBG_set(drbg, type, flags) == 0)
        goto err;

    if (parent != NULL) {
        if (drbg->strength > parent->strength) {
            goto err;
        }
    }

    return drbg;

    err:

    RAND_DRBG_free(drbg);
    eosio_assert(false, (char *)"rand_drbg_new");
    return NULL;
}

RAND_DRBG *RAND_DRBG_secure_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    return rand_drbg_new(1, type, flags, parent);
}



static RAND_DRBG *drbg_setup(RAND_DRBG *parent, int drbg_type)
{
    RAND_DRBG *drbg;

    drbg = RAND_DRBG_secure_new(rand_drbg_type[drbg_type],
                                rand_drbg_flags[drbg_type], parent);
    if (drbg == NULL)
        return NULL;

    /* Only the master DRBG needs to have a lock */
//    if (parent == NULL)
//        goto err;

    /* enable seed propagation */
    tsan_store(&drbg->reseed_prop_counter, 1);

    /*
     * Ignore instantiation error to support just-in-time instantiation.
     *
     * The state of the drbg will be checked in RAND_DRBG_generate() and
     * an automatic recovery is attempted.
     */
    (void)RAND_DRBG_instantiate(drbg,
                                (const unsigned char *) ossl_pers_string,
                                sizeof(ossl_pers_string) - 1);
    return drbg;

    err:
    RAND_DRBG_free(drbg);
    return NULL;
}


static RAND_DRBG *master_drbg;
RAND_DRBG *RAND_DRBG_get0_private(void)
{
    RAND_DRBG *drbg = NULL;

    master_drbg = drbg_setup(NULL, RAND_DRBG_TYPE_MASTER);
    if (master_drbg == NULL)
        eosio_assert(false, (char *)"RAND_DRBG_get0_private master_drbg error");

    drbg = drbg_setup(master_drbg, RAND_DRBG_TYPE_PRIVATE);
    if (drbg == NULL) {
        eosio_assert(false, (char *) "RAND_DRBG_get0_private drbg_setup error");
    }

    return drbg;
}

int RAND_priv_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    RAND_DRBG *drbg;
    int ret;

    if (meth != RAND_OpenSSL())
        return RAND_bytes(buf, num);

    drbg = RAND_DRBG_get0_private();
    if (drbg == NULL)
        eosio_assert(false, (char *)"RAND_priv_bytes drbg is error");


    ret = RAND_DRBG_bytes(drbg, buf, num);
    return ret;
}


void CRYPTO_clear_free(void *str, size_t num)
{
    if (str == NULL)
        return;
    if (num)
        OPENSSL_cleanse(str, num);
    CRYPTO_free(str);
}


int BN_cmp(const BIGNUM *a, const BIGNUM *b)
{
    int i;
    int gt, lt;
    BN_ULONG t1, t2;

    if ((a == NULL) || (b == NULL)) {
        if (a != NULL)
            return -1;
        else if (b != NULL)
            return 1;
        else
            return 0;
    }

    if (a->neg != b->neg) {
        if (a->neg)
            return -1;
        else
            return 1;
    }
    if (a->neg == 0) {
        gt = 1;
        lt = -1;
    } else {
        gt = -1;
        lt = 1;
    }

    if (a->top > b->top)
        return gt;
    if (a->top < b->top)
        return lt;
    for (i = a->top - 1; i >= 0; i--) {
        t1 = a->d[i];
        t2 = b->d[i];
        if (t1 > t2)
            return gt;
        if (t1 < t2)
            return lt;
    }
    return 0;
}

static int bnrand(BNRAND_FLAG flag, BIGNUM *rnd, int bits, int top, int bottom)
{
    unsigned char *buf = NULL;
    int b, ret = 0, bit, bytes, mask;

    if (bits == 0) {
        if (top != BN_RAND_TOP_ANY || bottom != BN_RAND_BOTTOM_ANY)
            goto toosmall;
        BN_zero(rnd);
        return 1;
    }
    if (bits < 0 || (bits == 1 && top > 0))
        goto toosmall;

    bytes = (bits + 7) / 8;
    bit = (bits - 1) % 8;
    mask = 0xff << (bit + 1);

    buf = (unsigned char *)CRYPTO_malloc(bytes);
    if (buf == NULL) {
        goto err;
    }

    /* make a random number and set the top and bottom bits */
    b = flag == NORMAL ? RAND_bytes(buf, bytes) : RAND_priv_bytes(buf, bytes);
    if (b <= 0)
        goto err;

    if (flag == TESTING) {
        int i;
        unsigned char c;

        for (i = 0; i < bytes; i++) {
            if (RAND_bytes(&c, 1) <= 0)
                goto err;
            if (c >= 128 && i > 0)
                buf[i] = buf[i - 1];
            else if (c < 42)
                buf[i] = 0;
            else if (c < 84)
                buf[i] = 255;
        }
    }

    if (top >= 0) {
        if (top) {
            if (bit == 0) {
                buf[0] = 1;
                buf[1] |= 0x80;
            } else {
                buf[0] |= (3 << (bit - 1));
            }
        } else {
            buf[0] |= (1 << bit);
        }
    }
    buf[0] &= ~mask;
    if (bottom)                 /* set bottom bit if requested */
        buf[bytes - 1] |= 1;
    if (!BN_bin2bn(buf, bytes, rnd))
        goto err;
    ret = 1;
    CRYPTO_clear_free(buf, bytes);
    return ret;
    err:
    CRYPTO_clear_free(buf, bytes);
    eosio_assert(false,(char *)"bnrand error");
    return ret;

    toosmall:
    eosio_assert(false,(char *)"BN_F_BNRAND, BN_R_BITS_TOO_SMALL");
    return 0;
}


BN_ULONG bn_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                      int n)
{
    BN_ULONG t1, t2;
    int c = 0;

    assert(n >= 0);
    if (n <= 0)
        return (BN_ULONG)0;

    while (n) {
        t1 = a[0];
        t2 = b[0];
        r[0] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        a++;
        b++;
        r++;
        n--;
    }
    return c;
}

int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max, min, dif;
    BN_ULONG t1, t2, borrow, *rp;
    const BN_ULONG *ap, *bp;
    max = a->top;
    min = b->top;
    dif = max - min;

    if (dif < 0) {              /* hmm... should not be happening */
        eosio_assert(false,"BN_F_BN_USUB, BN_R_ARG2_LT_ARG3");
        return 0;
    }

    if (bn_wexpand(r, max) == NULL)
        return 0;

    ap = a->d;
    bp = b->d;
    rp = r->d;

    borrow = bn_sub_words(rp, ap, bp, min);
    ap += min;
    rp += min;

    while (dif) {
        dif--;
        t1 = *(ap++);
        t2 = (t1 - borrow) & BN_MASK2;
        *(rp++) = t2;
        borrow &= (t1 == 0);
    }

    while (max && *--rp == 0)
        max--;

    r->top = max;
    r->neg = 0;
    return 1;
}

#  define BN_ULLONG       unsigned long long

int BN_abs_is_word(const BIGNUM *a, const BN_ULONG w)
{
    return ((a->top == 1) && (a->d[0] == w)) || ((w == 0) && (a->top == 0));
}

# define BN_one(a)       (BN_set_word((a),1))
void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags)
{
    dest->d = b->d;
    dest->top = b->top;
    dest->dmax = b->dmax;
    dest->neg = b->neg;
    dest->flags = ((dest->flags & BN_FLG_MALLOCED)
                   | (b->flags & ~BN_FLG_MALLOCED)
                   | BN_FLG_STATIC_DATA | flags);
}


int BN_lshift(BIGNUM *r, const BIGNUM *a, int n)
{
    int i, nw, lb, rb;
    BN_ULONG *t, *f;
    BN_ULONG l;
    if (n < 0) {
        eosio_assert(false,"BN_F_BN_LSHIFT, BN_R_INVALID_SHIFT");
        return 0;
    }

    nw = n / BN_BITS2;
    if (bn_wexpand(r, a->top + nw + 1) == NULL)
        return 0;
    r->neg = a->neg;
    lb = n % BN_BITS2;
    rb = BN_BITS2 - lb;
    f = a->d;
    t = r->d;
    t[a->top + nw] = 0;
    if (lb == 0)
        for (i = a->top - 1; i >= 0; i--)
            t[nw + i] = f[i];
    else
        for (i = a->top - 1; i >= 0; i--) {
            l = f[i];
            t[nw + i + 1] |= (l >> rb) & BN_MASK2;
            t[nw + i] = (l << lb) & BN_MASK2;
        }
    memset(t, 0, sizeof(*t) * nw);
    r->top = a->top + nw + 1;
    bn_correct_top(r);
    return 1;
}

#  define BN_MASK2l       (0xffffffffL)
#  define BN_BITS4        32
#  define BN_MASK2h1      (0xffffffff80000000L)

#  define LBITS(a)        ((a)&BN_MASK2l)
#  define HBITS(a)        (((a)>>BN_BITS4)&BN_MASK2l)
#  define L2HBITS(a)      (((a)<<BN_BITS4)&BN_MASK2)

#  define LLBITS(a)       ((a)&BN_MASKl)
#  define LHBITS(a)       (((a)>>BN_BITS2)&BN_MASKl)
#  define LL2HBITS(a)     ((BN_ULLONG)((a)&BN_MASKl)<<BN_BITS2)



#   define BN_UMULT_LOHI(low,high,a,b) ({       \
        __uint128_t ret=(__uint128_t)(a)*(b);   \
        (high)=ret>>64; (low)=ret;      })

#  define mul_add(r,a,w,c) {              \
        BN_ULONG high,low,ret,tmp=(a);  \
        ret =  (r);                     \
        BN_UMULT_LOHI(low,high,w,tmp);  \
        ret += (c);                     \
        (c) =  (ret<(c))?1:0;           \
        (c) += high;                    \
        ret += low;                     \
        (c) += (ret<low)?1:0;           \
        (r) =  ret;                     \
        }

#  define mul(r,a,w,c)    {               \
        BN_ULONG high,low,ret,ta=(a);   \
        BN_UMULT_LOHI(low,high,w,ta);   \
        ret =  low + (c);               \
        (c) =  high;                    \
        (c) += (ret<low)?1:0;           \
        (r) =  ret;                     \
        }

#  define sqr(r0,r1,a)    {               \
        BN_ULONG tmp=(a);               \
        BN_UMULT_LOHI(r0,r1,tmp,tmp);   \
        }


BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n)
{
    int i, j, nw, lb, rb;
    BN_ULONG *t, *f;
    BN_ULONG l, tmp;
    if (n < 0) {
        eosio_assert(false, (char *)"BN_F_BN_RSHIFT, BN_R_INVALID_SHIFT");
        return 0;
    }

    nw = n / BN_BITS2;
    rb = n % BN_BITS2;
    lb = BN_BITS2 - rb;
    if (nw >= a->top || a->top == 0) {
        BN_zero(r);
        return 1;
    }
    i = (BN_num_bits(a) - n + (BN_BITS2 - 1)) / BN_BITS2;
    if (r != a) {
        if (bn_wexpand(r, i) == NULL)
            return 0;
        r->neg = a->neg;
    } else {
        if (n == 0)
            return 1;           /* or the copying loop will go berserk */
    }

    f = &(a->d[nw]);
    t = r->d;
    j = a->top - nw;
    r->top = i;

    if (rb == 0) {
        for (i = j; i != 0; i--)
            *(t++) = *(f++);
    } else {
        l = *(f++);
        for (i = j - 1; i != 0; i--) {
            tmp = (l >> rb) & BN_MASK2;
            l = *(f++);
            *(t++) = (tmp | (l << lb)) & BN_MASK2;
        }
        if ((l = (l >> rb) & BN_MASK2))
            *(t) = l;
    }
    if (!r->top)
        r->neg = 0; /* don't allow negative zero */
    return 1;
}

void BN_CTX_end(BN_CTX *ctx);

BN_ULONG bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                      int n)
{
    BN_ULONG c, l, t;

    assert(n >= 0);
    if (n <= 0)
        return (BN_ULONG)0;

    c = 0;
    while (n) {
        t = a[0];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[0]) & BN_MASK2;
        c += (l < t);
        r[0] = l;
        a++;
        b++;
        r++;
        n--;
    }
    return (BN_ULONG)c;
}

#  define BN_MASK2h       (0xffffffff00000000L)
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
{
    BN_ULONG dh, dl, q, ret = 0, th, tl, t;
    int i, count = 2;

    if (d == 0)
        return BN_MASK2;

    i = BN_num_bits_word(d);
    assert((i == BN_BITS2) || (h <= (BN_ULONG)1 << i));

    i = BN_BITS2 - i;
    if (h >= d)
        h -= d;

    if (i) {
        d <<= i;
        h = (h << i) | (l >> (BN_BITS2 - i));
        l <<= i;
    }
    dh = (d & BN_MASK2h) >> BN_BITS4;
    dl = (d & BN_MASK2l);
    for (;;) {
        if ((h >> BN_BITS4) == dh)
            q = BN_MASK2l;
        else
            q = h / dh;

        th = q * dh;
        tl = dl * q;
        for (;;) {
            t = h - th;
            if ((t & BN_MASK2h) ||
                ((tl) <= ((t << BN_BITS4) | ((l & BN_MASK2h) >> BN_BITS4))))
                break;
            q--;
            th -= dh;
            tl -= dl;
        }
        t = (tl >> BN_BITS4);
        tl = (tl << BN_BITS4) & BN_MASK2h;
        th += t;

        if (l < tl)
            th++;
        l -= tl;
        if (h < th) {
            h += d;
            q--;
        }
        h -= th;

        if (--count == 0)
            break;

        ret = q << BN_BITS4;
        h = ((h << BN_BITS4) | (l >> BN_BITS4)) & BN_MASK2;
        l = (l & BN_MASK2l) << BN_BITS4;
    }
    ret |= q;
    return ret;
}

int BN_div(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor,
           BN_CTX *ctx)
{
    int norm_shift, i, loop;
    BIGNUM *tmp, wnum, *snum, *sdiv, *res;
    BN_ULONG *resp, *wnump;
    BN_ULONG d0, d1;
    int num_n, div_n;
    int no_branch = 0;

    if ((num->top > 0 && num->d[num->top - 1] == 0) ||
        (divisor->top > 0 && divisor->d[divisor->top - 1] == 0)) {
        eosio_assert(false,"BN_F_BN_DIV, BN_R_NOT_INITIALIZED");
        return 0;
    }

    if ((BN_get_flags(num, BN_FLG_CONSTTIME) != 0)
        || (BN_get_flags(divisor, BN_FLG_CONSTTIME) != 0)) {
        no_branch = 1;
    }

    if (BN_is_zero(divisor)) {
        eosio_assert(false,"BN_F_BN_DIV, BN_R_DIV_BY_ZERO");
        return 0;
    }

    if (!no_branch && BN_ucmp(num, divisor) < 0) {
        if (rm != NULL) {
            if (BN_copy(rm, num) == NULL)
                return 0;
        }
        if (dv != NULL)
            BN_zero(dv);
        return 1;
    }

    BN_CTX_start(ctx);
    res = (dv == NULL) ? BN_CTX_get(ctx) : dv;
    tmp = BN_CTX_get(ctx);
    snum = BN_CTX_get(ctx);
    sdiv = BN_CTX_get(ctx);
    if (sdiv == NULL)
        goto err;

    /* First we normalise the numbers */
    norm_shift = BN_BITS2 - ((BN_num_bits(divisor)) % BN_BITS2);
    //r=a*2^n
    if (!(BN_lshift(sdiv, divisor, norm_shift)))
        goto err;
    sdiv->neg = 0;
    norm_shift += BN_BITS2;
    if (!(BN_lshift(snum, num, norm_shift)))
        goto err;
    snum->neg = 0;

    if (no_branch) {
        /*
         * Since we don't know whether snum is larger than sdiv, we pad snum
         * with enough zeroes without changing its value.
         */
        if (snum->top <= sdiv->top + 1) {
            if (bn_wexpand(snum, sdiv->top + 2) == NULL)
                goto err;
            for (i = snum->top; i < sdiv->top + 2; i++)
                snum->d[i] = 0;
            snum->top = sdiv->top + 2;
        } else {
            if (bn_wexpand(snum, snum->top + 1) == NULL)
                goto err;
            snum->d[snum->top] = 0;
            snum->top++;
        }
    }

    div_n = sdiv->top;
    num_n = snum->top;
    loop = num_n - div_n;
    /*
     * Lets setup a 'window' into snum This is the part that corresponds to
     * the current 'area' being divided
     */
    wnum.neg = 0;
    wnum.d = &(snum->d[loop]);
    wnum.top = div_n;
    wnum.flags = BN_FLG_STATIC_DATA;
    /*
     * only needed when BN_ucmp messes up the values between top and max
     */
    wnum.dmax = snum->dmax - loop; /* so we don't step out of bounds */

    /* Get the top 2 words of sdiv */
    /* div_n=sdiv->top; */
    d0 = sdiv->d[div_n - 1];
    d1 = (div_n == 1) ? 0 : sdiv->d[div_n - 2];

    /* pointer to the 'top' of snum */
    wnump = &(snum->d[num_n - 1]);

    /* Setup to 'res' */
    if (!bn_wexpand(res, (loop + 1)))
        goto err;
    res->neg = (num->neg ^ divisor->neg);
    res->top = loop - no_branch;
    resp = &(res->d[loop - 1]);

    /* space for temp */
    if (!bn_wexpand(tmp, (div_n + 1)))
        goto err;

    if (!no_branch) {
        if (BN_ucmp(&wnum, sdiv) >= 0) {
            bn_sub_words(wnum.d, wnum.d, sdiv->d, div_n);
            *resp = 1;
        } else
            res->top--;
    }

    /* Increase the resp pointer so that we never create an invalid pointer. */
    resp++;

    if (res->top == 0)
        res->neg = 0;
    else
        resp--;

    for (i = 0; i < loop - 1; i++, wnump--) {
        BN_ULONG q, l0;
        BN_ULONG n0, n1, rem = 0;

        n0 = wnump[0];
        n1 = wnump[-1];
        if (n0 == d0)
            q = BN_MASK2;
        else {                  /* n0 < d0 */

            BN_ULONG t2l, t2h;
            q = bn_div_words(n0, n1, d0);
            rem = (n1 - q * d0) & BN_MASK2;
            BN_UMULT_LOHI(t2l, t2h, d1, q);


            for (;;) {
                if ((t2h < rem) || ((t2h == rem) && (t2l <= wnump[-2])))
                    break;
                q--;
                rem += d0;
                if (rem < d0)
                    break;      /* don't let rem overflow */
                if (t2l < d1)
                    t2h--;
                t2l -= d1;
            }

        }



        l0 = bn_mul_words(tmp->d, sdiv->d, div_n, q);
        tmp->d[div_n] = l0;
        wnum.d--;
        //wnum.d = wnum.d - tmp->d
        if (bn_sub_words(wnum.d, wnum.d, tmp->d, div_n + 1)) {
            q--;
            if (bn_add_words(wnum.d, wnum.d, sdiv->d, div_n))
                (*wnump)++;
        }

        resp--;
        *resp = q;
    }

    bn_correct_top(snum);
    if (rm != NULL) {

        int neg = num->neg;
        //r=a/2^n
        BN_rshift(rm, snum, norm_shift);
        if (!BN_is_zero(rm))
            rm->neg = neg;
    }

    if (no_branch)
        bn_correct_top(res);
    BN_CTX_end(ctx);
    return 1;
    err:
    BN_CTX_end(ctx);
    return 0;
}


# define BN_TBIT        ((BN_ULONG)1 << (BN_BITS2 - 1))
# define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_is_odd(const BIGNUM *a);
int BN_is_one(const BIGNUM *a)
{
    return BN_abs_is_word(a, 1) && !a->neg;
}

int BN_is_word(const BIGNUM *a, const BN_ULONG w)
{
    return BN_abs_is_word(a, w) && (!w || !a->neg);
}

int BN_rshift1(BIGNUM *r, const BIGNUM *a)
{
    BN_ULONG *ap, *rp, t, c;
    int i, j;

    if (BN_is_zero(a)) {
        BN_zero(r);
        return 1;
    }
    i = a->top;
    ap = a->d;
    j = i - (ap[i - 1] == 1);
    if (a != r) {
        if (bn_wexpand(r, j) == NULL)
            return 0;
        r->neg = a->neg;
    }
    rp = r->d;
    t = ap[--i];
    c = (t & 1) ? BN_TBIT : 0;
    if (t >>= 1)
        rp[i] = t;
    while (i > 0) {
        t = ap[--i];
        rp[i] = ((t >> 1) & BN_MASK2) | c;
        c = (t & 1) ? BN_TBIT : 0;
    }
    r->top = j;
    if (!r->top)
        r->neg = 0; /* don't allow negative zero */
    return 1;
}

int BN_lshift1(BIGNUM *r, const BIGNUM *a)
{
    BN_ULONG *ap, *rp, t, c;
    int i;

    if (r != a) {
        r->neg = a->neg;
        if (bn_wexpand(r, a->top + 1) == NULL)
            return 0;
        r->top = a->top;
    } else {
        if (bn_wexpand(r, a->top + 1) == NULL)
            return 0;
    }
    ap = a->d;
    rp = r->d;
    c = 0;
    for (i = 0; i < a->top; i++) {
        t = *(ap++);
        *(rp++) = ((t << 1) | c) & BN_MASK2;
        c = (t & BN_TBIT) ? 1 : 0;
    }
    if (c) {
        *rp = 1;
        r->top++;
    }
    return 1;
}

int BN_mul_word(BIGNUM *a, BN_ULONG w)
{
    BN_ULONG ll;

    w &= BN_MASK2;
    if (a->top) {
        if (w == 0)
            BN_zero(a);
        else {
            ll = bn_mul_words(a->d, a->d, a->top, w);
            if (ll) {
                if (bn_wexpand(a, a->top + 1) == NULL)
                    return 0;
                a->d[a->top++] = ll;
            }
        }
    }

    return 1;
}


int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
    if (!(BN_mod(r, m, d, ctx)))
        return 0;
    if (!r->neg)
        return 1;
    /* now   -|d| < r < 0,  so we have to set  r := r + |d| */
    return (d->neg ? BN_sub : BN_add) (r, r, d);
}

static BIGNUM *BN_mod_inverse_no_branch(BIGNUM *in,
                                        const BIGNUM *a, const BIGNUM *n,
                                        BN_CTX *ctx)
{
    BIGNUM *A, *B, *X, *Y, *M, *D, *T, *R = NULL;
    BIGNUM *ret = NULL;
    int sign;

    BN_CTX_start(ctx);
    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx);
    M = BN_CTX_get(ctx);
    Y = BN_CTX_get(ctx);
    T = BN_CTX_get(ctx);
    if (T == NULL)
        goto err;

    if (in == NULL)
        R = BN_new();
    else
        R = in;
    if (R == NULL)
        goto err;

    BN_one(X);
    BN_zero(Y);
    if (BN_copy(B, a) == NULL)
        goto err;
    if (BN_copy(A, n) == NULL)
        goto err;
    A->neg = 0;

    if (B->neg || (BN_ucmp(B, A) >= 0)) {
        {
            BIGNUM local_B;
            bn_init(&local_B);
            BN_with_flags(&local_B, B, BN_FLG_CONSTTIME);
            if (!BN_nnmod(B, &local_B, A, ctx))
                goto err;
            /* Ensure local_B goes out of scope before any further use of B */
        }
    }
    sign = -1;
    while (!BN_is_zero(B)) {
        BIGNUM *tmp;
        {
            BIGNUM local_A;
            bn_init(&local_A);
            BN_with_flags(&local_A, A, BN_FLG_CONSTTIME);

            /* (D, M) := (A/B, A%B) ... */
            if (!BN_div(D, M, &local_A, B, ctx))
                goto err;
            /* Ensure local_A goes out of scope before any further use of A */
        }

        /*-
         * Now
         *      A = D*B + M;
         * thus we have
         * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
         */

        tmp = A;                /* keep the BIGNUM object, the value does not
                                 * matter */

        /* (A, B) := (B, A mod B) ... */
        A = B;
        B = M;
        if (!BN_mul(tmp, D, X, ctx))
            goto err;
        if (!BN_add(tmp, tmp, Y))
            goto err;

        M = Y;                  /* keep the BIGNUM object, the value does not
                                 * matter */
        Y = X;
        X = tmp;
        sign = -sign;
    }

    if (sign < 0) {
        if (!BN_sub(Y, n, Y))
            goto err;
    }
    /* Now  Y*a  ==  A  (mod |n|).  */

    if (BN_is_one(A)) {
        /* Y*a == 1  (mod |n|) */
        if (!Y->neg && BN_ucmp(Y, n) < 0) {
            if (!BN_copy(R, Y))
                goto err;
        } else {
            if (!BN_nnmod(R, Y, n, ctx))
                goto err;
        }
    } else {
        goto err;
    }
    ret = R;
    err:
    if ((ret == NULL) && (in == NULL))
        BN_free(R);
    BN_CTX_end(ctx);
    return ret;
}


BIGNUM *int_bn_mod_inverse(BIGNUM *in,
                           const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx,
                           int *pnoinv)
{
    BIGNUM *A, *B, *X, *Y, *M, *D, *T, *R = NULL;
    BIGNUM *ret = NULL;
    int sign;

    /* This is invalid input so we don't worry about constant time here */
    if (BN_abs_is_word(n, 1) || BN_is_zero(n)) {
        if (pnoinv != NULL)
            *pnoinv = 1;
        return NULL;
    }

    if (pnoinv != NULL)
        *pnoinv = 0;

    if ((BN_get_flags(a, BN_FLG_CONSTTIME) != 0)
        || (BN_get_flags(n, BN_FLG_CONSTTIME) != 0)) {
        return BN_mod_inverse_no_branch(in, a, n, ctx);
    }

    BN_CTX_start(ctx);
    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx);
    M = BN_CTX_get(ctx);
    Y = BN_CTX_get(ctx);
    T = BN_CTX_get(ctx);
    if (T == NULL)
        goto err;

    if (in == NULL)
        R = BN_new();
    else
        R = in;
    if (R == NULL)
        goto err;

    BN_one(X);
    BN_zero(Y);
    if (BN_copy(B, a) == NULL)
        goto err;
    if (BN_copy(A, n) == NULL)
        goto err;
    A->neg = 0;
    if (B->neg || (BN_ucmp(B, A) >= 0)) {
        if (!BN_nnmod(B, B, A, ctx))
            goto err;
    }
    sign = -1;
    /*-
     * From  B = a mod |n|,  A = |n|  it follows that
     *
     *      0 <= B < A,
     *     -sign*X*a  ==  B   (mod |n|),
     *      sign*Y*a  ==  A   (mod |n|).
     */

    if (BN_is_odd(n) && (BN_num_bits(n) <= 2048)) {
        /*
         * Binary inversion algorithm; requires odd modulus. This is faster
         * than the general algorithm if the modulus is sufficiently small
         * (about 400 .. 500 bits on 32-bit systems, but much more on 64-bit
         * systems)
         */
        int shift;

        while (!BN_is_zero(B)) {
            /*-
             *      0 < B < |n|,
             *      0 < A <= |n|,
             * (1) -sign*X*a  ==  B   (mod |n|),
             * (2)  sign*Y*a  ==  A   (mod |n|)
             */

            /*
             * Now divide B by the maximum possible power of two in the
             * integers, and divide X by the same value mod |n|. When we're
             * done, (1) still holds.
             */
            shift = 0;
            while (!BN_is_bit_set(B, shift)) { /* note that 0 < B */
                shift++;

                if (BN_is_odd(X)) {
                    if (!BN_uadd(X, X, n))
                        goto err;
                }
                /*
                 * now X is even, so we can easily divide it by two
                 */
                if (!BN_rshift1(X, X))
                    goto err;
            }
            if (shift > 0) {
                if (!BN_rshift(B, B, shift))
                    goto err;
            }

            /*
             * Same for A and Y.  Afterwards, (2) still holds.
             */
            shift = 0;
            while (!BN_is_bit_set(A, shift)) { /* note that 0 < A */
                shift++;

                if (BN_is_odd(Y)) {
                    if (!BN_uadd(Y, Y, n))
                        goto err;
                }
                /* now Y is even */
                if (!BN_rshift1(Y, Y))
                    goto err;
            }
            if (shift > 0) {
                if (!BN_rshift(A, A, shift))
                    goto err;
            }

            /*-
             * We still have (1) and (2).
             * Both  A  and  B  are odd.
             * The following computations ensure that
             *
             *     0 <= B < |n|,
             *      0 < A < |n|,
             * (1) -sign*X*a  ==  B   (mod |n|),
             * (2)  sign*Y*a  ==  A   (mod |n|),
             *
             * and that either  A  or  B  is even in the next iteration.
             */
            if (BN_ucmp(B, A) >= 0) {
                /* -sign*(X + Y)*a == B - A  (mod |n|) */
                if (!BN_uadd(X, X, Y))
                    goto err;
                /*
                 * NB: we could use BN_mod_add_quick(X, X, Y, n), but that
                 * actually makes the algorithm slower
                 */
                if (!BN_usub(B, B, A))
                    goto err;
            } else {
                /*  sign*(X + Y)*a == A - B  (mod |n|) */
                if (!BN_uadd(Y, Y, X))
                    goto err;
                /*
                 * as above, BN_mod_add_quick(Y, Y, X, n) would slow things down
                 */
                if (!BN_usub(A, A, B))
                    goto err;
            }
        }
    } else {
        /* general inversion algorithm */

        while (!BN_is_zero(B)) {
            BIGNUM *tmp;

            /*-
             *      0 < B < A,
             * (*) -sign*X*a  ==  B   (mod |n|),
             *      sign*Y*a  ==  A   (mod |n|)
             */

            /* (D, M) := (A/B, A%B) ... */
            if (BN_num_bits(A) == BN_num_bits(B)) {
                if (!BN_one(D))
                    goto err;
                if (!BN_sub(M, A, B))
                    goto err;
            } else if (BN_num_bits(A) == BN_num_bits(B) + 1) {
                /* A/B is 1, 2, or 3 */
                if (!BN_lshift1(T, B))
                    goto err;
                if (BN_ucmp(A, T) < 0) {
                    /* A < 2*B, so D=1 */
                    if (!BN_one(D))
                        goto err;
                    if (!BN_sub(M, A, B))
                        goto err;
                } else {
                    /* A >= 2*B, so D=2 or D=3 */
                    if (!BN_sub(M, A, T))
                        goto err;
                    if (!BN_add(D, T, B))
                        goto err; /* use D (:= 3*B) as temp */
                    if (BN_ucmp(A, D) < 0) {
                        /* A < 3*B, so D=2 */
                        if (!BN_set_word(D, 2))
                            goto err;
                        /*
                         * M (= A - 2*B) already has the correct value
                         */
                    } else {
                        /* only D=3 remains */
                        if (!BN_set_word(D, 3))
                            goto err;
                        /*
                         * currently M = A - 2*B, but we need M = A - 3*B
                         */
                        if (!BN_sub(M, M, B))
                            goto err;
                    }
                }
            } else {
                if (!BN_div(D, M, A, B, ctx))
                    goto err;
            }

            /*-
             * Now
             *      A = D*B + M;
             * thus we have
             * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
             */

            tmp = A;    /* keep the BIGNUM object, the value does not matter */

            /* (A, B) := (B, A mod B) ... */
            A = B;
            B = M;
            /* ... so we have  0 <= B < A  again */

            /*-
             * Since the former  M  is now  B  and the former  B  is now  A,
             * (**) translates into
             *       sign*Y*a  ==  D*A + B    (mod |n|),
             * i.e.
             *       sign*Y*a - D*A  ==  B    (mod |n|).
             * Similarly, (*) translates into
             *      -sign*X*a  ==  A          (mod |n|).
             *
             * Thus,
             *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
             * i.e.
             *        sign*(Y + D*X)*a  ==  B  (mod |n|).
             *
             * So if we set  (X, Y, sign) := (Y + D*X, X, -sign), we arrive back at
             *      -sign*X*a  ==  B   (mod |n|),
             *       sign*Y*a  ==  A   (mod |n|).
             * Note that  X  and  Y  stay non-negative all the time.
             */

            /*
             * most of the time D is very small, so we can optimize tmp := D*X+Y
             */
            if (BN_is_one(D)) {
                if (!BN_add(tmp, X, Y))
                    goto err;
            } else {
                if (BN_is_word(D, 2)) {
                    if (!BN_lshift1(tmp, X))
                        goto err;
                } else if (BN_is_word(D, 4)) {
                    if (!BN_lshift(tmp, X, 2))
                        goto err;
                } else if (D->top == 1) {
                    if (!BN_copy(tmp, X))
                        goto err;
                    if (!BN_mul_word(tmp, D->d[0]))
                        goto err;
                } else {
                    if (!BN_mul(tmp, D, X, ctx))
                        goto err;
                }
                if (!BN_add(tmp, tmp, Y))
                    goto err;
            }

            M = Y;      /* keep the BIGNUM object, the value does not matter */
            Y = X;
            X = tmp;
            sign = -sign;
        }
    }

    /*-
     * The while loop (Euclid's algorithm) ends when
     *      A == gcd(a,n);
     * we have
     *       sign*Y*a  ==  A  (mod |n|),
     * where  Y  is non-negative.
     */

    if (sign < 0) {
        if (!BN_sub(Y, n, Y))
            goto err;
    }
    /* Now  Y*a  ==  A  (mod |n|).  */

    if (BN_is_one(A)) {
        /* Y*a == 1  (mod |n|) */
        if (!Y->neg && BN_ucmp(Y, n) < 0) {
            if (!BN_copy(R, Y))
                goto err;
        } else {
            if (!BN_nnmod(R, Y, n, ctx))
                goto err;
        }
    } else {
        if (pnoinv)
            *pnoinv = 1;
        goto err;
    }
    ret = R;


    err:
    if ((ret == NULL) && (in == NULL))
        BN_free(R);
    BN_CTX_end(ctx);
    return ret;
}


int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max, min, dif;
    const BN_ULONG *ap, *bp;
    BN_ULONG *rp, carry, t1, t2;
    if (a->top < b->top) {
        const BIGNUM *tmp;

        tmp = a;
        a = b;
        b = tmp;
    }
    max = a->top;
    min = b->top;
    dif = max - min;

    if (bn_wexpand(r, max + 1) == NULL)
        return 0;

    r->top = max;

    ap = a->d;
    bp = b->d;
    rp = r->d;

    carry = bn_add_words(rp, ap, bp, min);
    rp += min;
    ap += min;

    while (dif) {
        dif--;
        t1 = *(ap++);
        t2 = (t1 + carry) & BN_MASK2;
        *(rp++) = t2;
        carry &= (t2 == 0);
    }
    *rp = carry;
    r->top += carry;

    r->neg = 0;
    return 1;
}

/* signed sub of b from a. */
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int ret, r_neg, cmp_res;
    if (a->neg != b->neg) {
        r_neg = a->neg;
        ret = BN_uadd(r, a, b);
    } else {
        cmp_res = BN_ucmp(a, b);
        if (cmp_res > 0) {
            r_neg = a->neg;
            ret = BN_usub(r, a, b);
        } else if (cmp_res < 0) {
            r_neg = !b->neg;
            ret = BN_usub(r, b, a);
        } else {
            r_neg = 0;
            BN_zero(r);
            ret = 1;
        }
    }

    r->neg = r_neg;
    return ret;
}

/* random number r:  0 <= r < range */
static int bnrand_range(BNRAND_FLAG flag, BIGNUM *r, const BIGNUM *range)
{
    int n;
    int count = 100;

    if (range->neg || BN_is_zero(range)) {
        eosio_assert(false, "BN_F_BNRAND_RANGE, BN_R_INVALID_RANGE");
        return 0;
    }

    n = BN_num_bits(range);     /* n > 0 */
    if (n == 1)
        BN_zero(r);
    else if (!BN_is_bit_set(range, n - 2) && !BN_is_bit_set(range, n - 3)) {
        do {
            if (!bnrand(flag, r, n + 1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
                return 0;

            if (BN_cmp(r, range) >= 0) {
                if (!BN_sub(r, r, range))
                    return 0;
                if (BN_cmp(r, range) >= 0)
                    if (!BN_sub(r, r, range))
                        return 0;
            }

            if (!--count) {
                eosio_assert(false,"BN_F_BNRAND_RANGE, BN_R_TOO_MANY_ITERATIONS");
                return 0;
            }

        }
        while (BN_cmp(r, range) >= 0);
    } else {
        do {
            /* range = 11..._2  or  range = 101..._2 */
            if (!bnrand(flag, r, n, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
                return 0;

            if (!--count) {
                eosio_assert(false,"BN_F_BNRAND_RANGE, BN_R_TOO_MANY_ITERATIONS");
                return 0;
            }
        }
        while (BN_cmp(r, range) >= 0);
    }

    return 1;
}

int BN_priv_rand_range(BIGNUM *r, const BIGNUM *range)
{
    return bnrand_range(PRIVATE, r, range);
}

int BN_is_odd(const BIGNUM *a)
{
    return (a->top > 0) && (a->d[0] & 1);
}


BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num,
                          BN_ULONG w)
{
    BN_ULONG c1 = 0;

    if (num <= 0)
        return c1;

    while (num & ~3) {
        mul_add(rp[0], ap[0], w, c1);
        mul_add(rp[1], ap[1], w, c1);
        mul_add(rp[2], ap[2], w, c1);
        mul_add(rp[3], ap[3], w, c1);
        ap += 4;
        rp += 4;
        num -= 4;
    }
    if (num) {
        mul_add(rp[0], ap[0], w, c1);
        if (--num == 0)
            return c1;
        mul_add(rp[1], ap[1], w, c1);
        if (--num == 0)
            return c1;
        mul_add(rp[2], ap[2], w, c1);
        return c1;
    }

    return c1;
}

BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
    BN_ULONG c1 = 0;

    if (num <= 0)
        return c1;

    while (num & ~3) {
        mul(rp[0], ap[0], w, c1);
        mul(rp[1], ap[1], w, c1);
        mul(rp[2], ap[2], w, c1);
        mul(rp[3], ap[3], w, c1);
        ap += 4;
        rp += 4;
        num -= 4;
    }
    if (num) {
        mul(rp[0], ap[0], w, c1);
        if (--num == 0)
            return c1;
        mul(rp[1], ap[1], w, c1);
        if (--num == 0)
            return c1;
        mul(rp[2], ap[2], w, c1);
    }
    return c1;
}

void bn_sqr_words(BN_ULONG *r, const BN_ULONG *a, int n)
{
    if (n <= 0)
        return;

    while (n & ~3) {
        sqr(r[0], r[1], a[0]);
        sqr(r[2], r[3], a[1]);
        sqr(r[4], r[5], a[2]);
        sqr(r[6], r[7], a[3]);
        a += 4;
        r += 8;
        n -= 4;
    }
    if (n) {
        sqr(r[0], r[1], a[0]);
        if (--n == 0)
            return;
        sqr(r[2], r[3], a[1]);
        if (--n == 0)
            return;
        sqr(r[4], r[5], a[2]);
    }
}





# define BN_BLINDING_NO_UPDATE   0x00000001
void bn_sqr_normal(BN_ULONG *r, const BN_ULONG *a, int n, BN_ULONG *tmp)
{
    int i, j, max;
    const BN_ULONG *ap;
    BN_ULONG *rp;

    max = n * 2;
    ap = a;
    rp = r;
    rp[0] = rp[max - 1] = 0;
    rp++;
    j = n;

    if (--j > 0) {
        ap++;
        rp[j] = bn_mul_words(rp, ap, j, ap[-1]);
        rp += 2;
    }

    for (i = n - 2; i > 0; i--) {
        j--;
        ap++;
        rp[j] = bn_mul_add_words(rp, ap, j, ap[-1]);
        rp += 2;
    }

    bn_add_words(r, r, r, max);

    /* There will not be a carry */

    bn_sqr_words(tmp, a, n);

    bn_add_words(r, r, tmp, max);
}

static unsigned int BN_STACK_pop(BN_STACK *st)
{
    return st->indexes[--(st->depth)];
}

static void BN_POOL_release(BN_POOL *p, unsigned int num)
{
    unsigned int offset = (p->used - 1) % BN_CTX_POOL_SIZE;

    p->used -= num;
    while (num--) {
        if (offset == 0) {
            offset = BN_CTX_POOL_SIZE - 1;
            p->current = p->current->prev;
        } else
            offset--;
    }
}


void BN_CTX_end(BN_CTX *ctx)
{
    if (ctx->err_stack)
        ctx->err_stack--;
    else {
        unsigned int fp = BN_STACK_pop(&ctx->stack);
        /* Does this stack frame have anything to release? */
        if (fp < ctx->used)
            BN_POOL_release(&ctx->pool, ctx->used - fp);
        ctx->used = fp;
        /* Unjam "too_many" in case "get" had failed */
        ctx->too_many = 0;
    }
}

int bn_sqr_fixed_top(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
{
    int max, al;
    int ret = 0;
    BIGNUM *tmp, *rr;

    al = a->top;
    if (al <= 0) {
        r->top = 0;
        r->neg = 0;
        return 1;
    }

    BN_CTX_start(ctx);
    rr = (a != r) ? r : BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (rr == NULL || tmp == NULL)
        goto err;

    max = 2 * al;               /* Non-zero (from above) */
    if (bn_wexpand(rr, max) == NULL)
        goto err;

    if (al == 4) {
#ifndef BN_SQR_COMBA
        BN_ULONG t[8];
        bn_sqr_normal(rr->d, a->d, 4, t);
#else
        bn_sqr_comba4(rr->d, a->d);
#endif
    } else if (al == 8) {
#ifndef BN_SQR_COMBA
        BN_ULONG t[16];
        bn_sqr_normal(rr->d, a->d, 8, t);
#else
        bn_sqr_comba8(rr->d, a->d);
#endif
    } else {
#if defined(BN_RECURSION)
        if (al < BN_SQR_RECURSIVE_SIZE_NORMAL) {
            BN_ULONG t[BN_SQR_RECURSIVE_SIZE_NORMAL * 2];
            bn_sqr_normal(rr->d, a->d, al, t);
        } else {
            int j, k;

            j = BN_num_bits_word((BN_ULONG)al);
            j = 1 << (j - 1);
            k = j + j;
            if (al == j) {
                if (bn_wexpand(tmp, k * 2) == NULL)
                    goto err;
                bn_sqr_recursive(rr->d, a->d, al, tmp->d);
            } else {
                if (bn_wexpand(tmp, max) == NULL)
                    goto err;
                bn_sqr_normal(rr->d, a->d, al, tmp->d);
            }
        }
#else
        if (bn_wexpand(tmp, max) == NULL)
            goto err;
        bn_sqr_normal(rr->d, a->d, al, tmp->d);
#endif
    }

    rr->neg = 0;
    rr->top = max;
    rr->flags |= BN_FLG_FIXED_TOP;
    if (r != rr && BN_copy(r, rr) == NULL)
        goto err;

    ret = 1;
    err:
    BN_CTX_end(ctx);
    return ret;
}


void bn_mul_normal(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b, int nb)
{
    BN_ULONG *rr;

    if (na < nb) {
        int itmp;
        BN_ULONG *ltmp;

        itmp = na;
        na = nb;
        nb = itmp;
        ltmp = a;
        a = b;
        b = ltmp;

    }
    rr = &(r[na]);
    if (nb <= 0) {
        (void)bn_mul_words(r, a, na, 0);
        return;
    } else
        rr[0] = bn_mul_words(r, a, na, b[0]);

    for (;;) {
        if (--nb <= 0)
            return;
        rr[1] = bn_mul_add_words(&(r[1]), a, na, b[1]);
        if (--nb <= 0)
            return;
        rr[2] = bn_mul_add_words(&(r[2]), a, na, b[2]);
        if (--nb <= 0)
            return;
        rr[3] = bn_mul_add_words(&(r[3]), a, na, b[3]);
        if (--nb <= 0)
            return;
        rr[4] = bn_mul_add_words(&(r[4]), a, na, b[4]);
        rr += 4;
        r += 4;
        b += 4;
    }
}


# define BN_MULL_SIZE_NORMAL                     (16)/* 32 */
# define BN_MUL_RECURSIVE_SIZE_NORMAL            (16)/* 32 less than */

BN_ULONG bn_sub_part_words(BN_ULONG *r,
                           const BN_ULONG *a, const BN_ULONG *b,
                           int cl, int dl)
{
    BN_ULONG c, t;

    assert(cl >= 0);
    c = bn_sub_words(r, a, b, cl);

    if (dl == 0)
        return c;

    r += cl;
    a += cl;
    b += cl;

    if (dl < 0) {
        for (;;) {
            t = b[0];
            r[0] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            t = b[1];
            r[1] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            t = b[2];
            r[2] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            t = b[3];
            r[3] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            b += 4;
            r += 4;
        }
    } else {
        int save_dl = dl;
        while (c) {
            t = a[0];
            r[0] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            t = a[1];
            r[1] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            t = a[2];
            r[2] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            t = a[3];
            r[3] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            save_dl = dl;
            a += 4;
            r += 4;
        }
        if (dl > 0) {
            if (save_dl > dl) {
                switch (save_dl - dl) {
                    case 1:
                        r[1] = a[1];
                        if (--dl <= 0)
                            break;
                        /* fall thru */
                    case 2:
                        r[2] = a[2];
                        if (--dl <= 0)
                            break;
                        /* fall thru */
                    case 3:
                        r[3] = a[3];
                        if (--dl <= 0)
                            break;
                }
                a += 4;
                r += 4;
            }
        }
        if (dl > 0) {
            for (;;) {
                r[0] = a[0];
                if (--dl <= 0)
                    break;
                r[1] = a[1];
                if (--dl <= 0)
                    break;
                r[2] = a[2];
                if (--dl <= 0)
                    break;
                r[3] = a[3];
                if (--dl <= 0)
                    break;

                a += 4;
                r += 4;
            }
        }
    }
    return c;
}


int bn_cmp_words(const BN_ULONG *a, const BN_ULONG *b, int n)
{
    int i;
    BN_ULONG aa, bb;

    aa = a[n - 1];
    bb = b[n - 1];
    if (aa != bb)
        return ((aa > bb) ? 1 : -1);
    for (i = n - 2; i >= 0; i--) {
        aa = a[i];
        bb = b[i];
        if (aa != bb)
            return ((aa > bb) ? 1 : -1);
    }
    return 0;
}


int bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b, int cl, int dl)
{
    int n, i;
    n = cl - 1;

    if (dl < 0) {
        for (i = dl; i < 0; i++) {
            if (b[n - i] != 0)
                return -1;      /* a < b */
        }
    }
    if (dl > 0) {
        for (i = dl; i > 0; i--) {
            if (a[n + i] != 0)
                return 1;       /* a > b */
        }
    }
    return bn_cmp_words(a, b, cl);
}


#  define mul_add_c(a,b,c0,c1,c2)       do {    \
        BN_ULONG ta = (a), tb = (b);            \
        BN_ULONG lo, hi;                        \
        BN_UMULT_LOHI(lo,hi,ta,tb);             \
        c0 += lo; hi += (c0<lo)?1:0;            \
        c1 += hi; c2 += (c1<hi)?1:0;            \
        } while(0)


void bn_mul_comba8(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
{
    BN_ULONG c1, c2, c3;

    c1 = 0;
    c2 = 0;
    c3 = 0;
    mul_add_c(a[0], b[0], c1, c2, c3);
    r[0] = c1;
    c1 = 0;
    mul_add_c(a[0], b[1], c2, c3, c1);
    mul_add_c(a[1], b[0], c2, c3, c1);
    r[1] = c2;
    c2 = 0;
    mul_add_c(a[2], b[0], c3, c1, c2);
    mul_add_c(a[1], b[1], c3, c1, c2);
    mul_add_c(a[0], b[2], c3, c1, c2);
    r[2] = c3;
    c3 = 0;
    mul_add_c(a[0], b[3], c1, c2, c3);
    mul_add_c(a[1], b[2], c1, c2, c3);
    mul_add_c(a[2], b[1], c1, c2, c3);
    mul_add_c(a[3], b[0], c1, c2, c3);
    r[3] = c1;
    c1 = 0;
    mul_add_c(a[4], b[0], c2, c3, c1);
    mul_add_c(a[3], b[1], c2, c3, c1);
    mul_add_c(a[2], b[2], c2, c3, c1);
    mul_add_c(a[1], b[3], c2, c3, c1);
    mul_add_c(a[0], b[4], c2, c3, c1);
    r[4] = c2;
    c2 = 0;
    mul_add_c(a[0], b[5], c3, c1, c2);
    mul_add_c(a[1], b[4], c3, c1, c2);
    mul_add_c(a[2], b[3], c3, c1, c2);
    mul_add_c(a[3], b[2], c3, c1, c2);
    mul_add_c(a[4], b[1], c3, c1, c2);
    mul_add_c(a[5], b[0], c3, c1, c2);
    r[5] = c3;
    c3 = 0;
    mul_add_c(a[6], b[0], c1, c2, c3);
    mul_add_c(a[5], b[1], c1, c2, c3);
    mul_add_c(a[4], b[2], c1, c2, c3);
    mul_add_c(a[3], b[3], c1, c2, c3);
    mul_add_c(a[2], b[4], c1, c2, c3);
    mul_add_c(a[1], b[5], c1, c2, c3);
    mul_add_c(a[0], b[6], c1, c2, c3);
    r[6] = c1;
    c1 = 0;
    mul_add_c(a[0], b[7], c2, c3, c1);
    mul_add_c(a[1], b[6], c2, c3, c1);
    mul_add_c(a[2], b[5], c2, c3, c1);
    mul_add_c(a[3], b[4], c2, c3, c1);
    mul_add_c(a[4], b[3], c2, c3, c1);
    mul_add_c(a[5], b[2], c2, c3, c1);
    mul_add_c(a[6], b[1], c2, c3, c1);
    mul_add_c(a[7], b[0], c2, c3, c1);
    r[7] = c2;
    c2 = 0;
    mul_add_c(a[7], b[1], c3, c1, c2);
    mul_add_c(a[6], b[2], c3, c1, c2);
    mul_add_c(a[5], b[3], c3, c1, c2);
    mul_add_c(a[4], b[4], c3, c1, c2);
    mul_add_c(a[3], b[5], c3, c1, c2);
    mul_add_c(a[2], b[6], c3, c1, c2);
    mul_add_c(a[1], b[7], c3, c1, c2);
    r[8] = c3;
    c3 = 0;
    mul_add_c(a[2], b[7], c1, c2, c3);
    mul_add_c(a[3], b[6], c1, c2, c3);
    mul_add_c(a[4], b[5], c1, c2, c3);
    mul_add_c(a[5], b[4], c1, c2, c3);
    mul_add_c(a[6], b[3], c1, c2, c3);
    mul_add_c(a[7], b[2], c1, c2, c3);
    r[9] = c1;
    c1 = 0;
    mul_add_c(a[7], b[3], c2, c3, c1);
    mul_add_c(a[6], b[4], c2, c3, c1);
    mul_add_c(a[5], b[5], c2, c3, c1);
    mul_add_c(a[4], b[6], c2, c3, c1);
    mul_add_c(a[3], b[7], c2, c3, c1);
    r[10] = c2;
    c2 = 0;
    mul_add_c(a[4], b[7], c3, c1, c2);
    mul_add_c(a[5], b[6], c3, c1, c2);
    mul_add_c(a[6], b[5], c3, c1, c2);
    mul_add_c(a[7], b[4], c3, c1, c2);
    r[11] = c3;
    c3 = 0;
    mul_add_c(a[7], b[5], c1, c2, c3);
    mul_add_c(a[6], b[6], c1, c2, c3);
    mul_add_c(a[5], b[7], c1, c2, c3);
    r[12] = c1;
    c1 = 0;
    mul_add_c(a[6], b[7], c2, c3, c1);
    mul_add_c(a[7], b[6], c2, c3, c1);
    r[13] = c2;
    c2 = 0;
    mul_add_c(a[7], b[7], c3, c1, c2);
    r[14] = c3;
    r[15] = c1;
}

void bn_mul_comba4(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
{
    BN_ULONG c1, c2, c3;

    c1 = 0;
    c2 = 0;
    c3 = 0;
    mul_add_c(a[0], b[0], c1, c2, c3);
    r[0] = c1;
    c1 = 0;
    mul_add_c(a[0], b[1], c2, c3, c1);
    mul_add_c(a[1], b[0], c2, c3, c1);
    r[1] = c2;
    c2 = 0;
    mul_add_c(a[2], b[0], c3, c1, c2);
    mul_add_c(a[1], b[1], c3, c1, c2);
    mul_add_c(a[0], b[2], c3, c1, c2);
    r[2] = c3;
    c3 = 0;
    mul_add_c(a[0], b[3], c1, c2, c3);
    mul_add_c(a[1], b[2], c1, c2, c3);
    mul_add_c(a[2], b[1], c1, c2, c3);
    mul_add_c(a[3], b[0], c1, c2, c3);
    r[3] = c1;
    c1 = 0;
    mul_add_c(a[3], b[1], c2, c3, c1);
    mul_add_c(a[2], b[2], c2, c3, c1);
    mul_add_c(a[1], b[3], c2, c3, c1);
    r[4] = c2;
    c2 = 0;
    mul_add_c(a[2], b[3], c3, c1, c2);
    mul_add_c(a[3], b[2], c3, c1, c2);
    r[5] = c3;
    c3 = 0;
    mul_add_c(a[3], b[3], c1, c2, c3);
    r[6] = c1;
    r[7] = c2;
}


void bn_mul_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2,
                      int dna, int dnb, BN_ULONG *t)
{
    int n = n2 / 2, c1, c2;
    int tna = n + dna, tnb = n + dnb;
    unsigned int neg, zero;
    BN_ULONG ln, lo, *p;

    /*
     * Only call bn_mul_comba 8 if n2 == 8 and the two arrays are complete
     * [steve]
     */
    if (n2 == 8 && dna == 0 && dnb == 0) {
        bn_mul_comba8(r, a, b);
        return;
    }

    /* Else do normal multiply */
    if (n2 < BN_MUL_RECURSIVE_SIZE_NORMAL) {
        bn_mul_normal(r, a, n2 + dna, b, n2 + dnb);
        if ((dna + dnb) < 0)
            memset(&r[2 * n2 + dna + dnb], 0,
                   sizeof(BN_ULONG) * -(dna + dnb));
        return;
    }
    /* r=(a[0]-a[1])*(b[1]-b[0]) */
    c1 = bn_cmp_part_words(a, &(a[n]), tna, n - tna);
    c2 = bn_cmp_part_words(&(b[n]), b, tnb, tnb - n);
    zero = neg = 0;
    switch (c1 * 3 + c2) {
        case -4:
            bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
            bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
            break;
        case -3:
            zero = 1;
            break;
        case -2:
            bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
            bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n); /* + */
            neg = 1;
            break;
        case -1:
        case 0:
        case 1:
            zero = 1;
            break;
        case 2:
            bn_sub_part_words(t, a, &(a[n]), tna, n - tna); /* + */
            bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
            neg = 1;
            break;
        case 3:
            zero = 1;
            break;
        case 4:
            bn_sub_part_words(t, a, &(a[n]), tna, n - tna);
            bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n);
            break;
    }

    if (n == 4 && dna == 0 && dnb == 0) { /* XXX: bn_mul_comba4 could take
                                           * extra args to do this well */
        if (!zero)
            bn_mul_comba4(&(t[n2]), t, &(t[n]));
        else
            memset(&t[n2], 0, sizeof(*t) * 8);

        bn_mul_comba4(r, a, b);
        bn_mul_comba4(&(r[n2]), &(a[n]), &(b[n]));
    } else if (n == 8 && dna == 0 && dnb == 0) { /* XXX: bn_mul_comba8 could
                                                  * take extra args to do
                                                  * this well */
        if (!zero)
            bn_mul_comba8(&(t[n2]), t, &(t[n]));
        else
            memset(&t[n2], 0, sizeof(*t) * 16);

        bn_mul_comba8(r, a, b);
        bn_mul_comba8(&(r[n2]), &(a[n]), &(b[n]));
    } else         /* BN_MUL_COMBA */
    {
        p = &(t[n2 * 2]);
        if (!zero)
            bn_mul_recursive(&(t[n2]), t, &(t[n]), n, 0, 0, p);
        else
            memset(&t[n2], 0, sizeof(*t) * n2);
        bn_mul_recursive(r, a, b, n, 0, 0, p);
        bn_mul_recursive(&(r[n2]), &(a[n]), &(b[n]), n, dna, dnb, p);
    }

    /*-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     */

    c1 = (int)(bn_add_words(t, r, &(r[n2]), n2));

    if (neg) {                  /* if t[32] is negative */
        c1 -= (int)(bn_sub_words(&(t[n2]), t, &(t[n2]), n2));
    } else {
        /* Might have a carry */
        c1 += (int)(bn_add_words(&(t[n2]), &(t[n2]), t, n2));
    }

    /*-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     * c1 holds the carry bits
     */
    c1 += (int)(bn_add_words(&(r[n]), &(r[n]), &(t[n2]), n2));
    if (c1) {
        p = &(r[n + n2]);
        lo = *p;
        ln = (lo + c1) & BN_MASK2;
        *p = ln;

        /*
         * The overflow will stop before we over write words we should not
         * overwrite
         */
        if (ln < (BN_ULONG)c1) {
            do {
                p++;
                lo = *p;
                ln = (lo + 1) & BN_MASK2;
                *p = ln;
            } while (ln == 0);
        }
    }
}


int bn_mul_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int ret = 0;
    int top, al, bl;
    BIGNUM *rr;
    al = a->top;
    bl = b->top;
    int i;
    BIGNUM *t = NULL;
    int j = 0, k;

    if ((al == 0) || (bl == 0)) {
        BN_zero(r);
        return 1;
    }
    top = al + bl;

    BN_CTX_start(ctx);
    if ((r == a) || (r == b)) {
        if ((rr = BN_CTX_get(ctx)) == NULL)
            goto err;
    } else
        rr = r;

    i = al - bl;

    if (i == 0) {
        if (al == 8) {
            eosio_assert(false, (char *)"i == 0");
        }
    }

    if ((al >= BN_MULL_SIZE_NORMAL) && (bl >= BN_MULL_SIZE_NORMAL)) {
        if (i >= -1 && i <= 1) {
            /*
             * Find out the power of two lower or equal to the longest of the
             * two numbers
             */
            if (i >= 0) {
                j = BN_num_bits_word((BN_ULONG)al);
            }
            if (i == -1) {
                j = BN_num_bits_word((BN_ULONG)bl);
            }
            j = 1 << (j - 1);
            assert(j <= al || j <= bl);
            k = j + j;
            t = BN_CTX_get(ctx);
            if (t == NULL)
                goto err;
            if (al > j || bl > j) {
                eosio_assert(false,(char *)"al > j || bl > j");
            } else {            /* al <= j || bl <= j */
                if (bn_wexpand(t, k * 2) == NULL)
                    goto err;
                if (bn_wexpand(rr, k * 2) == NULL)
                    goto err;
                bn_mul_recursive(rr->d, a->d, b->d, j, al - j, bl - j, t->d);
            }
            rr->top = top;
            goto end;
        }
    }

    if (bn_wexpand(rr, top) == NULL)
        goto err;
    rr->top = top;
    bn_mul_normal(rr->d, a->d, al, b->d, bl);

    end:
    rr->neg = a->neg ^ b->neg;
    rr->flags |= BN_FLG_FIXED_TOP;
    if (r != rr && BN_copy(r, rr) == NULL)
        goto err;

    ret = 1;
    err:
    BN_CTX_end(ctx);
    return ret;
}


int BN_mask_bits(BIGNUM *a, int n)
{
    int b, w;

    if (n < 0)
        return 0;

    w = n / BN_BITS2;
    b = n % BN_BITS2;
    if (w >= a->top)
        return 0;
    if (b == 0)
        a->top = w;
    else {
        a->top = w + 1;
        a->d[w] &= ~(BN_MASK2 << b);
    }
    bn_correct_top(a);
    return 1;
}


int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int ret = bn_mul_fixed_top(r, a, b, ctx);

    bn_correct_top(r);

    return ret;
}

int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int ret, r_neg, cmp_res;

    if (a->neg == b->neg) {
        r_neg = a->neg;
        ret = BN_uadd(r, a, b);
    } else {
        cmp_res = BN_ucmp(a, b);
        if (cmp_res > 0) {
            r_neg = a->neg;
            ret = BN_usub(r, a, b);
        } else if (cmp_res < 0) {
            r_neg = b->neg;
            ret = BN_usub(r, b, a);
        } else {
            r_neg = 0;
            BN_zero(r);
            ret = 1;
        }
    }

    r->neg = r_neg;
    return ret;
}

static int bn_from_montgomery_word(BIGNUM *ret, BIGNUM *r, BN_MONT_CTX *mont)
{
    BIGNUM *n;
    BN_ULONG *ap, *np, *rp, n0, v, carry;
    int nl, max, i;
    unsigned int rtop;

    n = &(mont->N);
    nl = n->top;
    if (nl == 0) {
        ret->top = 0;
        return 1;
    }

    max = (2 * nl);             /* carry is stored separately */
    if (bn_wexpand(r, max) == NULL)
        return 0;

    r->neg ^= n->neg;
    np = n->d;
    rp = r->d;

    /* clear the top words of T */
    for (rtop = r->top, i = 0; i < max; i++) {
        v = (BN_ULONG)0 - ((i - rtop) >> (8 * sizeof(rtop) - 1));
        rp[i] &= v;
    }

    r->top = max;
    r->flags |= BN_FLG_FIXED_TOP;
    n0 = mont->n0[0];

    /*
     * Add multiples of |n| to |r| until R = 2^(nl * BN_BITS2) divides it. On
     * input, we had |r| < |n| * R, so now |r| < 2 * |n| * R. Note that |r|
     * includes |carry| which is stored separately.
     */
    for (carry = 0, i = 0; i < nl; i++, rp++) {
        v = bn_mul_add_words(rp, np, nl, (rp[0] * n0) & BN_MASK2);
        v = (v + carry + rp[nl]) & BN_MASK2;
        carry |= (v != rp[nl]);
        carry &= (v <= rp[nl]);
        rp[nl] = v;
    }

    if (bn_wexpand(ret, nl) == NULL)
        return 0;
    ret->top = nl;
    ret->flags |= BN_FLG_FIXED_TOP;
    ret->neg = r->neg;

    rp = ret->d;

    /*
     * Shift |nl| words to divide by R. We have |ap| < 2 * |n|. Note that |ap|
     * includes |carry| which is stored separately.
     */
    ap = &(r->d[nl]);

    carry -= bn_sub_words(rp, ap, np, nl);
    /*
     * |carry| is -1 if |ap| - |np| underflowed or zero if it did not. Note
     * |carry| cannot be 1. That would imply the subtraction did not fit in
     * |nl| words, and we know at most one subtraction is needed.
     */
    for (i = 0; i < nl; i++) {
        rp[i] = (carry & ap[i]) | (~carry & rp[i]);
        ap[i] = 0;
    }

    return 1;
}

int bn_from_mont_fixed_top(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
                           BN_CTX *ctx)
{
    int retn = 0;
    BIGNUM *t;

    BN_CTX_start(ctx);
    if ((t = BN_CTX_get(ctx)) && BN_copy(t, a)) {
        retn = bn_from_montgomery_word(ret, t, mont);
    }
    BN_CTX_end(ctx);

    return retn;
}


int BN_from_montgomery(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
                       BN_CTX *ctx)
{
    int retn;

    retn = bn_from_mont_fixed_top(ret, a, mont, ctx);
    bn_correct_top(ret);

    return retn;
}

int bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                const BN_ULONG *np, const BN_ULONG *n0p, int num)
{
    BN_ULONG c0, c1, *tp, n0 = *n0p;
    volatile BN_ULONG *vp;
    int i = 0, j;

    vp = tp = ( BN_ULONG *)alloca((num + 2) * sizeof(BN_ULONG));

    for (i = 0; i <= num; i++)
        tp[i] = 0;

    for (i = 0; i < num; i++) {
        c0 = bn_mul_add_words(tp, ap, num, bp[i]);
        c1 = (tp[num] + c0) & BN_MASK2;
        tp[num] = c1;
        tp[num + 1] = (c1 < c0 ? 1 : 0);

        c0 = bn_mul_add_words(tp, np, num, tp[0] * n0);
        c1 = (tp[num] + c0) & BN_MASK2;
        tp[num] = c1;
        tp[num + 1] += (c1 < c0 ? 1 : 0);
        for (j = 0; j <= num; j++)
            tp[j] = tp[j + 1];
    }

    if (tp[num] != 0 || tp[num - 1] >= np[num - 1]) {
        c0 = bn_sub_words(rp, tp, np, num);
        if (tp[num] != 0 || c0 == 0) {
            for (i = 0; i < num + 2; i++)
                vp[i] = 0;
            return 1;
        }
    }
    for (i = 0; i < num; i++)
        rp[i] = tp[i], vp[i] = 0;
    vp[num] = 0;
    vp[num + 1] = 0;
    return 1;
}


int bn_mul_mont_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx)
{
    BIGNUM *tmp;
    int ret = 0;
    int num = mont->N.top;

    if (num > 1 && a->top == num && b->top == num) {
        if (bn_wexpand(r, num) == NULL)
            return 0;
        if (bn_mul_mont(r->d, a->d, b->d, mont->N.d, mont->n0, num)) {
            r->neg = a->neg ^ b->neg;
            r->top = num;
            r->flags |= BN_FLG_FIXED_TOP;
            return 1;
        }
    }

    if ((a->top + b->top) > 2 * num)
        return 0;

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

    if (a == b) {
        if (!bn_sqr_fixed_top(tmp, a, ctx))
            goto err;
    } else {
        if (!bn_mul_fixed_top(tmp, a, b, ctx))
            goto err;
    }
    /* reduce from aRR to aR */
    if (!bn_from_montgomery_word(r, tmp, mont))
        goto err;
    ret = 1;
    err:
    BN_CTX_end(ctx);
    return ret;
}

int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
{
    int ret = bn_sqr_fixed_top(r, a, ctx);

    bn_correct_top(r);

    return ret;
}



int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx)
{
    BIGNUM *t;
    int ret = 0;


    BN_CTX_start(ctx);
    if ((t = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (a == b) {
        if (!BN_sqr(t, a, ctx))
            goto err;
    } else {
        if (!BN_mul(t, a, b, ctx))
            goto err;
    }
    if (!BN_nnmod(r, t, m, ctx))
        goto err;
    ret = 1;
    err:
    BN_CTX_end(ctx);
    return ret;
}

int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx)
{
    int ret = bn_mul_mont_fixed_top(r, a, b, mont, ctx);

    bn_correct_top(r);
    return ret;
}

int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *ctx)
{
    int ret = 1;
    if ((b->A == NULL) || (b->Ai == NULL)) {
        eosio_assert(false, (char *)"BN_BLINDING_convert_ex (b->A == NULL) || (b->Ai == NULL)");
    }

    if (b->counter == -1)
        b->counter = 0;
    else if (!BN_BLINDING_update(b, ctx))
        return 0;

    if (r != NULL && (BN_copy(r, b->Ai) == NULL))
        return 0;

    if (b->m_ctx != NULL)
        ret = BN_mod_mul_montgomery(n, n, b->A, b->m_ctx, ctx);
    else
        ret = BN_mod_mul(n, n, b->A, b->mod, ctx);

    return ret;
}

static int rsa_blinding_convert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind,BN_CTX *ctx)
{
    if (unblind == NULL) {
        return BN_BLINDING_convert_ex(f, NULL, b, ctx);
    } else {
        int ret;
        ret = BN_BLINDING_convert_ex(f, unblind, b, ctx);
        return ret;
    }
}

void BN_clear_free(BIGNUM *a)
{
    if (a == NULL)
        return;
    if (a->d != NULL && !BN_get_flags(a, BN_FLG_STATIC_DATA)) {
        OPENSSL_cleanse(a->d, a->dmax * sizeof(a->d[0]));
        bn_free_d(a);
    }
    if (BN_get_flags(a, BN_FLG_MALLOCED)) {
        OPENSSL_cleanse(a, sizeof(*a));
        CRYPTO_free(a);
    }
}

static void BN_POOL_finish(BN_POOL *p)
{
    unsigned int loop;
    BIGNUM *bn;

    while (p->head) {
        for (loop = 0, bn = p->head->vals; loop++ < BN_CTX_POOL_SIZE; bn++)
            if (bn->d)
                BN_clear_free(bn);
        p->current = p->head->next;
        CRYPTO_free(p->head);
        p->head = p->current;
    }
}


static void BN_STACK_finish(BN_STACK *st)
{
    CRYPTO_free(st->indexes);
    st->indexes = NULL;
}

void BN_CTX_free(BN_CTX *ctx)
{
    if (ctx == NULL)
        return;
    BN_STACK_finish(&ctx->stack);
    BN_POOL_finish(&ctx->pool);
    CRYPTO_free(ctx);
}

#define RSA_MAX_PRIME_NUM       5
#define RSA_MIN_MODULUS_BITS    512
#define TABLE_SIZE      32

int BN_is_negative(const BIGNUM *a)
{
    return (a->neg != 0);
}

void BN_MONT_CTX_free(BN_MONT_CTX *mont)
{
    if (mont == NULL)
        return;
    BN_clear_free(&mont->RR);
    BN_clear_free(&mont->N);
    BN_clear_free(&mont->Ni);
    if (mont->flags & BN_FLG_MALLOCED)
        CRYPTO_free(mont);
}


# define BN_F_BNRAND                                      127
# define BN_F_BNRAND_RANGE                                138
# define BN_F_BN_BLINDING_CONVERT_EX                      100
# define BN_F_BN_BLINDING_CREATE_PARAM                    128
# define BN_F_BN_BLINDING_INVERT_EX                       101
# define BN_F_BN_BLINDING_NEW                             102
# define BN_F_BN_BLINDING_UPDATE                          103
# define BN_F_BN_BN2DEC                                   104
# define BN_F_BN_BN2HEX                                   105
# define BN_F_BN_COMPUTE_WNAF                             142
# define BN_F_BN_CTX_GET                                  116
# define BN_F_BN_CTX_NEW                                  106
# define BN_F_BN_CTX_START                                129
# define BN_F_BN_DIV                                      107
# define BN_F_BN_DIV_RECP                                 130
# define BN_F_BN_EXP                                      123
# define BN_F_BN_EXPAND_INTERNAL                          120
# define BN_F_BN_GENCB_NEW                                143
# define BN_F_BN_GENERATE_DSA_NONCE                       140
# define BN_F_BN_GENERATE_PRIME_EX                        141
# define BN_F_BN_GF2M_MOD                                 131
# define BN_F_BN_GF2M_MOD_EXP                             132
# define BN_F_BN_GF2M_MOD_MUL                             133
# define BN_F_BN_GF2M_MOD_SOLVE_QUAD                      134
# define BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR                  135
# define BN_F_BN_GF2M_MOD_SQR                             136
# define BN_F_BN_GF2M_MOD_SQRT                            137
# define BN_F_BN_LSHIFT                                   145
# define BN_F_BN_MOD_EXP2_MONT                            118
# define BN_F_BN_MOD_EXP_MONT                             109
# define BN_F_BN_MOD_EXP_MONT_CONSTTIME                   124
# define BN_F_BN_MOD_EXP_MONT_WORD                        117
# define BN_F_BN_MOD_EXP_RECP                             125
# define BN_F_BN_MOD_EXP_SIMPLE                           126
# define BN_F_BN_MOD_INVERSE                              110
# define BN_F_BN_MOD_INVERSE_NO_BRANCH                    139
# define BN_F_BN_MOD_LSHIFT_QUICK                         119
# define BN_F_BN_MOD_SQRT                                 121
# define BN_F_BN_MONT_CTX_NEW                             149
# define BN_F_BN_MPI2BN                                   112
# define BN_F_BN_NEW                                      113
# define BN_F_BN_POOL_GET                                 147
# define BN_F_BN_RAND                                     114
# define BN_F_BN_RAND_RANGE                               122
# define BN_F_BN_RECP_CTX_NEW                             150
# define BN_F_BN_RSHIFT                                   146
# define BN_F_BN_SET_WORDS                                144
# define BN_F_BN_STACK_PUSH                               148
# define BN_F_BN_USUB                                     115
# define MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH      ( 64 )
# define MOD_EXP_CTIME_MIN_CACHE_LINE_MASK       (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - 1)
# define BN_R_ARG2_LT_ARG3                                100
# define BN_R_BAD_RECIPROCAL                              101
# define BN_R_BIGNUM_TOO_LONG                             114
# define BN_R_BITS_TOO_SMALL                              118
# define BN_R_CALLED_WITH_EVEN_MODULUS                    102
# define BN_R_DIV_BY_ZERO                                 103
# define BN_R_ENCODING_ERROR                              104
# define BN_R_EXPAND_ON_STATIC_BIGNUM_DATA                105
# define BN_R_INPUT_NOT_REDUCED                           110
# define BN_R_INVALID_LENGTH                              106
# define BN_R_INVALID_RANGE                               115
# define BN_R_INVALID_SHIFT                               119
# define BN_R_NOT_A_SQUARE                                111
# define BN_R_NOT_INITIALIZED                             107
# define BN_R_NO_INVERSE                                  108
# define BN_R_NO_SOLUTION                                 116
# define BN_R_PRIVATE_KEY_TOO_LARGE                       117
# define BN_R_P_IS_NOT_PRIME                              112
# define BN_R_TOO_MANY_ITERATIONS                         113
# define BN_R_TOO_MANY_TEMPORARY_VARIABLES                109


void BN_MONT_CTX_init(BN_MONT_CTX *ctx)
{
    ctx->ri = 0;
    bn_init(&ctx->RR);
    bn_init(&ctx->N);
    bn_init(&ctx->Ni);
    ctx->n0[0] = ctx->n0[1] = 0;
    ctx->flags = 0;
}

BN_MONT_CTX *BN_MONT_CTX_new(void)
{
    BN_MONT_CTX *ret;

    if ((ret = (BN_MONT_CTX *)CRYPTO_malloc(sizeof(*ret))) == NULL) {
        eosio_assert(false, (char *)"BN_F_BN_MONT_CTX_NEW, ERR_R_MALLOC_FAILURE");
        return NULL;
    }

    BN_MONT_CTX_init(ret);
    ret->flags = BN_FLG_MALLOCED;
    return ret;
}


int BN_set_bit(BIGNUM *a, int n)
{
    int i, j, k;

    if (n < 0)
        return 0;

    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i) {
        if (bn_wexpand(a, i + 1) == NULL)
            return 0;
        for (k = a->top; k < i + 1; k++)
            a->d[k] = 0;
        a->top = i + 1;
        a->flags &= ~BN_FLG_FIXED_TOP;
    }

    a->d[i] |= (((BN_ULONG)1) << j);
    return 1;
}


BIGNUM *BN_mod_inverse(BIGNUM *in,
                       const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
    BIGNUM *rv;
    int noinv;
    rv = int_bn_mod_inverse(in, a, n, ctx, &noinv);
    if (noinv)
        eosio_assert(false, (char *)"BN_F_BN_MOD_INVERSE, BN_R_NO_INVERSE");
    return rv;
}

int BN_sub_word(BIGNUM *a, BN_ULONG w);
int BN_add_word(BIGNUM *a, BN_ULONG w)
{
    BN_ULONG l;
    int i;

    w &= BN_MASK2;

    /* degenerate case: w is zero */
    if (!w)
        return 1;
    /* degenerate case: a is zero */
    if (BN_is_zero(a))
        return BN_set_word(a, w);
    /* handle 'a' when negative */
    if (a->neg) {
        a->neg = 0;
        i = BN_sub_word(a, w);
        if (!BN_is_zero(a))
            a->neg = !(a->neg);
        return i;
    }
    for (i = 0; w != 0 && i < a->top; i++) {
        a->d[i] = l = (a->d[i] + w) & BN_MASK2;
        w = (w > l) ? 1 : 0;
    }
    if (w && i == a->top) {
        if (bn_wexpand(a, a->top + 1) == NULL)
            return 0;
        a->top++;
        a->d[i] = w;
    }
    return 1;
}

void BN_set_negative(BIGNUM *a, int b)
{
    if (b && !BN_is_zero(a))
        a->neg = 1;
    else
        a->neg = 0;
}

int BN_sub_word(BIGNUM *a, BN_ULONG w)
{
    int i;

    w &= BN_MASK2;

    /* degenerate case: w is zero */
    if (!w)
        return 1;
    /* degenerate case: a is zero */
    if (BN_is_zero(a)) {
        i = BN_set_word(a, w);
        if (i != 0)
            BN_set_negative(a, 1);
        return i;
    }
    /* handle 'a' when negative */
    if (a->neg) {
        a->neg = 0;
        i = BN_add_word(a, w);
        a->neg = 1;
        return i;
    }

    if ((a->top == 1) && (a->d[0] < w)) {
        a->d[0] = w - a->d[0];
        a->neg = 1;
        return 1;
    }
    i = 0;
    for (;;) {
        if (a->d[i] >= w) {
            a->d[i] -= w;
            break;
        } else {
            a->d[i] = (a->d[i] - w) & BN_MASK2;
            i++;
            w = 1;
        }
    }
    if ((a->d[i] == 0) && (i == (a->top - 1)))
        a->top--;
    return 1;
}

int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
{
    int i, ret = 0;
    BIGNUM *Ri, *R;

    if (BN_is_zero(mod))
        return 0;

    BN_CTX_start(ctx);
    if ((Ri = BN_CTX_get(ctx)) == NULL)
        goto err;
    R = &(mont->RR);            /* grab RR as a temp */
    if (!BN_copy(&(mont->N), mod))
        goto err;               /* Set N */
    if (BN_get_flags(mod, BN_FLG_CONSTTIME) != 0)
        BN_set_flags(&(mont->N), BN_FLG_CONSTTIME);
    mont->N.neg = 0;

    {
        BIGNUM tmod;
        BN_ULONG buf[2];

        bn_init(&tmod);
        tmod.d = buf;
        tmod.dmax = 2;
        tmod.neg = 0;

        if (BN_get_flags(mod, BN_FLG_CONSTTIME) != 0)
            BN_set_flags(&tmod, BN_FLG_CONSTTIME);

        mont->ri = (BN_num_bits(mod) + (BN_BITS2 - 1)) / BN_BITS2 * BN_BITS2;
        BN_zero(R);
        if (!(BN_set_bit(R, BN_BITS2)))
            goto err;           /* R */

        buf[0] = mod->d[0];     /* tmod = N mod word size */
        buf[1] = 0;
        tmod.top = buf[0] != 0 ? 1 : 0;
        /* Ri = R^-1 mod N */
        if (BN_is_one(&tmod))
            BN_zero(Ri);
        else if ((BN_mod_inverse(Ri, R, &tmod, ctx)) == NULL)
            goto err;
        if (!BN_lshift(Ri, Ri, BN_BITS2))
            goto err;           /* R*Ri */
        if (!BN_is_zero(Ri)) {
            if (!BN_sub_word(Ri, 1))
                goto err;
        } else {                /* if N mod word size == 1 */

            if (!BN_set_word(Ri, BN_MASK2))
                goto err;       /* Ri-- (mod word size) */
        }
        if (!BN_div(Ri, NULL, Ri, &tmod, ctx))
            goto err;
        /*
         * Ni = (R*Ri-1)/N, keep only least significant word:
         */
        mont->n0[0] = (Ri->top > 0) ? Ri->d[0] : 0;
        mont->n0[1] = 0;
    }

    /* setup RR for conversions */
    BN_zero(&(mont->RR));
    if (!BN_set_bit(&(mont->RR), mont->ri * 2))
        goto err;
    if (!BN_mod(&(mont->RR), &(mont->RR), &(mont->N), ctx))
        goto err;

    for (i = mont->RR.top, ret = mont->N.top; i < ret; i++)
        mont->RR.d[i] = 0;
    mont->RR.top = ret;
    mont->RR.flags |= BN_FLG_FIXED_TOP;

    ret = 1;
    err:
    BN_CTX_end(ctx);
    return ret;
}


#  define BN_window_bits_for_ctime_exponent_size(b) \
                ((b) > 937 ? 6 : \
                 (b) > 306 ? 5 : \
                 (b) >  89 ? 4 : \
                 (b) >  22 ? 3 : 1)
# define SPARCV9_TICK_PRIVILEGED (1<<0)
# define CFR_MONTMUL     0x00000200/* Supports MONTMUL opcodes */
# define CFR_MONTSQR     0x00000400/* Supports MONTSQR opcodes */

unsigned int OPENSSL_sparcv9cap_P[2] = { SPARCV9_TICK_PRIVILEGED, 0 };

#define MOD_EXP_CTIME_ALIGN(x_) \
        ((unsigned char*)(x_) + (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - (((size_t)(x_)) & (MOD_EXP_CTIME_MIN_CACHE_LINE_MASK))))

static int MOD_EXP_CTIME_COPY_TO_PREBUF(const BIGNUM *b, int top,
                                        unsigned char *buf, int idx,
                                        int window)
{
    int i, j;
    int width = 1 << window;
    BN_ULONG *table = (BN_ULONG *)buf;

    if (top > b->top)
        top = b->top;           /* this works because 'buf' is explicitly
                                 * zeroed */
    for (i = 0, j = idx; i < top; i++, j += width) {
        table[j] = b->d[i];
    }

    return 1;
}

static BN_ULONG bn_get_bits(const BIGNUM *a, int bitpos)
{
    BN_ULONG ret = 0;
    int wordpos;

    wordpos = bitpos / BN_BITS2;
    bitpos %= BN_BITS2;
    if (wordpos >= 0 && wordpos < a->top) {
        ret = a->d[wordpos] & BN_MASK2;
        if (bitpos) {
            ret >>= bitpos;
            if (++wordpos < a->top)
                ret |= a->d[wordpos] << (BN_BITS2 - bitpos);
        }
    }

    return ret & BN_MASK2;
}



const BIGNUM *BN_value_one(void)
{
    static const BN_ULONG data_one = 1L;
    static const BIGNUM const_one =
            { (BN_ULONG *)&data_one, 1, 1, 0, BN_FLG_STATIC_DATA };

    return &const_one;
}

int bn_to_mont_fixed_top(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                         BN_CTX *ctx)
{
    return bn_mul_mont_fixed_top(r, a, &(mont->RR), mont, ctx);
}

static unsigned int constant_time_msb(unsigned int a)
{
    return 0 - (a >> (sizeof(a) * 8 - 1));
}

static unsigned int constant_time_is_zero(unsigned int a)
{
    return constant_time_msb(~a & (a - 1));
}

static  unsigned int constant_time_eq(unsigned int a,
                                                 unsigned int b)
{
    return constant_time_is_zero(a ^ b);
}

static  unsigned int constant_time_eq_int(int a, int b)
{
    return constant_time_eq((unsigned)(a), (unsigned)(b));
}

static int MOD_EXP_CTIME_COPY_FROM_PREBUF(BIGNUM *b, int top,
                                          unsigned char *buf, int idx,
                                          int window)
{
    int i, j;
    int width = 1 << window;
    volatile BN_ULONG *table = (volatile BN_ULONG *)buf;

    if (bn_wexpand(b, top) == NULL)
        return 0;

    if (window <= 3) {
        for (i = 0; i < top; i++, table += width) {
            BN_ULONG acc = 0;

            for (j = 0; j < width; j++) {
                acc |= table[j] &
                       ((BN_ULONG)0 - (constant_time_eq_int(j,idx)&1));
            }

            b->d[i] = acc;
        }
    } else {
        int xstride = 1 << (window - 2);
        BN_ULONG y0, y1, y2, y3;

        i = idx >> (window - 2);        /* equivalent of idx / xstride */
        idx &= xstride - 1;             /* equivalent of idx % xstride */

        y0 = (BN_ULONG)0 - (constant_time_eq_int(i,0)&1);
        y1 = (BN_ULONG)0 - (constant_time_eq_int(i,1)&1);
        y2 = (BN_ULONG)0 - (constant_time_eq_int(i,2)&1);
        y3 = (BN_ULONG)0 - (constant_time_eq_int(i,3)&1);

        for (i = 0; i < top; i++, table += width) {
            BN_ULONG acc = 0;

            for (j = 0; j < xstride; j++) {
                acc |= ( (table[j + 0 * xstride] & y0) |
                         (table[j + 1 * xstride] & y1) |
                         (table[j + 2 * xstride] & y2) |
                         (table[j + 3 * xstride] & y3) )
                       & ((BN_ULONG)0 - (constant_time_eq_int(j,idx)&1));
            }

            b->d[i] = acc;
        }
    }

    b->top = top;
    b->flags |= BN_FLG_FIXED_TOP;
    return 1;
}



int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *in_mont)
{
    int i, bits, ret = 0, window, wvalue, wmask, window0;
    int top;
    BN_MONT_CTX *mont = NULL;

    int numPowers;
    unsigned char *powerbufFree = NULL;
    int powerbufLen = 0;
    unsigned char *powerbuf = NULL;
    BIGNUM tmp, am;
    unsigned int t4 = 0;

    if (!BN_is_odd(m)) {
        eosio_assert(false, (char *)"BN_F_BN_MOD_EXP_MONT_CONSTTIME, BN_R_CALLED_WITH_EVEN_MODULUS");
        return 0;
    }

    top = m->top;

    /*
     * Use all bits stored in |p|, rather than |BN_num_bits|, so we do not leak
     * whether the top bits are zero.
     */
    bits = p->top * BN_BITS2;
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }

    BN_CTX_start(ctx);

    /*
     * Allocate a montgomery context if it was not supplied by the caller. If
     * this is not done, things will break in the montgomery part.
     */
    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    /* Get the window size to use with size of p. */
    window = BN_window_bits_for_ctime_exponent_size(bits);
    if (window >= 5 && (top & 15) == 0 && top <= 64 &&
        (OPENSSL_sparcv9cap_P[1] & (CFR_MONTMUL | CFR_MONTSQR)) ==
        (CFR_MONTMUL | CFR_MONTSQR) && (t4 = OPENSSL_sparcv9cap_P[0]))
        window = 5;
    else
    if (window >= 5) {
        window = 5;             /* ~5% improvement for RSA2048 sign, and even
                                 * for RSA4096 */
        /* reserve space for mont->N.d[] copy */
        powerbufLen += top * sizeof(mont->N.d[0]);
    }
    (void)0;

    /*
     * Allocate a buffer large enough to hold all of the pre-computed powers
     * of am, am itself and tmp.
     */
    numPowers = 1 << window;
    powerbufLen += sizeof(m->d[0]) * (top * numPowers +
                                      ((2 * top) >
                                       numPowers ? (2 * top) : numPowers));
    if (powerbufLen < 3072)
        powerbufFree =
                (unsigned char *)alloca(powerbufLen + MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH);
    else
    if ((powerbufFree =
                 (unsigned char *)CRYPTO_malloc(powerbufLen + MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH))
        == NULL)
        goto err;

    powerbuf = MOD_EXP_CTIME_ALIGN(powerbufFree);
    memset(powerbuf, 0, powerbufLen);

    if (powerbufLen < 3072)
        powerbufFree = NULL;

    /* lay down tmp and am right after powers table */
    tmp.d = (BN_ULONG *)(powerbuf + sizeof(m->d[0]) * top * numPowers);
    am.d = tmp.d + top;
    tmp.top = am.top = 0;
    tmp.dmax = am.dmax = top;
    tmp.neg = am.neg = 0;
    tmp.flags = am.flags = BN_FLG_STATIC_DATA;

    /* prepare a^0 in Montgomery domain */     /* by Shay Gueron's suggestion */
    if (m->d[top - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1))) {
        /* 2^(top*BN_BITS2) - m */
        tmp.d[0] = (0 - m->d[0]) & BN_MASK2;
        for (i = 1; i < top; i++)
            tmp.d[i] = (~m->d[i]) & BN_MASK2;
        tmp.top = top;
    } else
    if (!bn_to_mont_fixed_top(&tmp, BN_value_one(), mont, ctx))
        goto err;

    /* prepare a^1 in Montgomery domain */
    if (a->neg || BN_ucmp(a, m) >= 0) {
        if (!BN_nnmod(&am, a, m, ctx))
            goto err;
        if (!bn_to_mont_fixed_top(&am, &am, mont, ctx))
            goto err;
    } else if (!bn_to_mont_fixed_top(&am, a, mont, ctx))
        goto err;


#if defined(OPENSSL_BN_ASM_MONT5)
    if (window == 5 && top > 1) {
        void bn_mul_mont_gather5(BN_ULONG *rp, const BN_ULONG *ap,
                                 const void *table, const BN_ULONG *np,
                                 const BN_ULONG *n0, int num, int power);
        void bn_scatter5(const BN_ULONG *inp, size_t num,
                         void *table, size_t power);
        void bn_gather5(BN_ULONG *out, size_t num, void *table, size_t power);
        void bn_power5(BN_ULONG *rp, const BN_ULONG *ap,
                       const void *table, const BN_ULONG *np,
                       const BN_ULONG *n0, int num, int power);
        int bn_get_bits5(const BN_ULONG *ap, int off);
        int bn_from_montgomery(BN_ULONG *rp, const BN_ULONG *ap,
                               const BN_ULONG *not_used, const BN_ULONG *np,
                               const BN_ULONG *n0, int num);

        BN_ULONG *n0 = mont->n0, *np;

        /*
         * BN_to_montgomery can contaminate words above .top [in
         * BN_DEBUG[_DEBUG] build]...
         */
        for (i = am.top; i < top; i++)
            am.d[i] = 0;
        for (i = tmp.top; i < top; i++)
            tmp.d[i] = 0;

        /*
         * copy mont->N.d[] to improve cache locality
         */
        for (np = am.d + top, i = 0; i < top; i++)
            np[i] = mont->N.d[i];

        bn_scatter5(tmp.d, top, powerbuf, 0);
        bn_scatter5(am.d, am.top, powerbuf, 1);
        bn_mul_mont(tmp.d, am.d, am.d, np, n0, top);
        bn_scatter5(tmp.d, top, powerbuf, 2);

# if 0
        for (i = 3; i < 32; i++) {
            /* Calculate a^i = a^(i-1) * a */
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
        }
# else
        /* same as above, but uses squaring for 1/2 of operations */
        for (i = 4; i < 32; i *= 2) {
            bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_scatter5(tmp.d, top, powerbuf, i);
        }
        for (i = 3; i < 8; i += 2) {
            int j;
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
            for (j = 2 * i; j < 32; j *= 2) {
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_scatter5(tmp.d, top, powerbuf, j);
            }
        }
        for (; i < 16; i += 2) {
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
            bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
            bn_scatter5(tmp.d, top, powerbuf, 2 * i);
        }
        for (; i < 32; i += 2) {
            bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            bn_scatter5(tmp.d, top, powerbuf, i);
        }
# endif
        window0 = (bits - 1) % 5 + 1;
        wmask = (1 << window0) - 1;
        bits -= window0;
        wvalue = bn_get_bits(p, bits) & wmask;
        bn_gather5(tmp.d, top, powerbuf, wvalue);

        /*
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         */
        if (top & 7) {
            while (bits > 0) {
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                bn_mul_mont_gather5(tmp.d, tmp.d, powerbuf, np, n0, top,
                                    bn_get_bits5(p->d, bits -= 5));
            }
        } else {
            while (bits > 0) {
                bn_power5(tmp.d, tmp.d, powerbuf, np, n0, top,
                          bn_get_bits5(p->d, bits -= 5));
            }
        }

        ret = bn_from_montgomery(tmp.d, tmp.d, NULL, np, n0, top);
        tmp.top = top;
        bn_correct_top(&tmp);
        if (ret) {
            if (!BN_copy(rr, &tmp))
                ret = 0;
            goto err;           /* non-zero ret means it's not error */
        }
    } else
#endif
    {
        if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, 0, window))
            goto err;
        if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&am, top, powerbuf, 1, window))
            goto err;

        /*
         * If the window size is greater than 1, then calculate
         * val[i=2..2^winsize-1]. Powers are computed as a*a^(i-1) (even
         * powers could instead be computed as (a^(i/2))^2 to use the slight
         * performance advantage of sqr over mul).
         */
        if (window > 1) {
            if (!bn_mul_mont_fixed_top(&tmp, &am, &am, mont, ctx))
                goto err;
            if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, 2,
                                              window))
                goto err;
            for (i = 3; i < numPowers; i++) {
                /* Calculate a^i = a^(i-1) * a */
                if (!bn_mul_mont_fixed_top(&tmp, &am, &tmp, mont, ctx))
                    goto err;
                if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, i,
                                                  window))
                    goto err;
            }
        }

        window0 = (bits - 1) % window + 1;
        wmask = (1 << window0) - 1;
        bits -= window0;
        wvalue = bn_get_bits(p, bits) & wmask;
        if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&tmp, top, powerbuf, wvalue,
                                            window))
            goto err;

        wmask = (1 << window) - 1;
        while (bits > 0) {

            /* Square the result window-size times */
            for (i = 0; i < window; i++)
                if (!bn_mul_mont_fixed_top(&tmp, &tmp, &tmp, mont, ctx))
                    goto err;

            bits -= window;
            wvalue = bn_get_bits(p, bits) & wmask;
            if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&am, top, powerbuf, wvalue,
                                                window))
                goto err;

            /* Multiply the result into the intermediate result */
            if (!bn_mul_mont_fixed_top(&tmp, &tmp, &am, mont, ctx))
                goto err;
        }
    }

#if defined(SPARC_T4_MONT)
    if (OPENSSL_sparcv9cap_P[0] & (SPARCV9_VIS3 | SPARCV9_PREFER_FPU)) {
        am.d[0] = 1;            /* borrow am */
        for (i = 1; i < top; i++)
            am.d[i] = 0;
        if (!BN_mod_mul_montgomery(rr, &tmp, &am, mont, ctx))
            goto err;
    } else
#endif
    if (!BN_from_montgomery(rr, &tmp, mont, ctx))
        goto err;
    ret = 1;
    err:
    if (in_mont == NULL)
        BN_MONT_CTX_free(mont);
    if (powerbuf != NULL) {
        OPENSSL_cleanse(powerbuf, powerbufLen);
        CRYPTO_free(powerbufFree);
    }
    BN_CTX_end(ctx);
    return ret;
}

# define BN_window_bits_for_exponent_size(b) \
                ((b) > 671 ? 6 : \
                 (b) > 239 ? 5 : \
                 (b) >  79 ? 4 : \
                 (b) >  23 ? 3 : 1)

int BN_mod_exp_mont(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{

    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *d, *r;
    const BIGNUM *aa;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];
    BN_MONT_CTX *mont = NULL;

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
        || BN_get_flags(a, BN_FLG_CONSTTIME) != 0
        || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        return BN_mod_exp_mont_consttime(rr, a, p, m, ctx, in_mont);
    }

    if (!BN_is_odd(m)) {
        eosio_assert(false, (char *)"BN_is_odd(m)");
        return 0;
    }

    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }

    BN_CTX_start(ctx);
    d = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    val[0] = BN_CTX_get(ctx);
    if (val[0] == NULL)
        goto err;

    /*
     * If this is not done, things will break in the montgomery part
     */

    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    if (a->neg || BN_ucmp(a, m) >= 0) {
        if (!BN_nnmod(val[0], a, m, ctx))
            goto err;
        aa = val[0];
    } else
        aa = a;
    if (!bn_to_mont_fixed_top(val[0], aa, mont, ctx))
        goto err;               /* 1 */

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!bn_mul_mont_fixed_top(d, val[0], val[0], mont, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
                !bn_mul_mont_fixed_top(val[i], val[i - 1], d, mont, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

#if 1                           /* by Shay Gueron's suggestion */
    j = m->top;                 /* borrow j */
    if (m->d[j - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1))) {
        if (bn_wexpand(r, j) == NULL)
            goto err;
        /* 2^(top*BN_BITS2) - m */
        r->d[0] = (0 - m->d[0]) & BN_MASK2;
        for (i = 1; i < j; i++)
            r->d[i] = (~m->d[i]) & BN_MASK2;
        r->top = j;
        r->flags |= BN_FLG_FIXED_TOP;
    } else
#endif
    if (!bn_to_mont_fixed_top(r, BN_value_one(), mont, ctx))
        goto err;
    for (;;) {
        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start) {
                if (!bn_mul_mont_fixed_top(r, r, r, mont, ctx))
                    goto err;
            }
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }

        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!bn_mul_mont_fixed_top(r, r, r, mont, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!bn_mul_mont_fixed_top(r, r, val[wvalue >> 1], mont, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }

#if defined(SPARC_T4_MONT)
    if (OPENSSL_sparcv9cap_P[0] & (SPARCV9_VIS3 | SPARCV9_PREFER_FPU)) {
        j = mont->N.top;        /* borrow j */
        val[0]->d[0] = 1;       /* borrow val[0] */
        for (i = 1; i < j; i++)
            val[0]->d[i] = 0;
        val[0]->top = j;
        if (!BN_mod_mul_montgomery(rr, r, val[0], mont, ctx))
            goto err;
    } else
#endif
    if (!BN_from_montgomery(rr, r, mont, ctx))
        goto err;
    ret = 1;
    err:
    if (in_mont == NULL)
        BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    return ret;
}



BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, void *lock,
                                    const BIGNUM *mod, BN_CTX *ctx)
{
    BN_MONT_CTX *ret;
    ret = *pmont;
    if (ret)
        return ret;

    /*
     * We don't want to serialise globally while doing our lazy-init math in
     * BN_MONT_CTX_set. That punishes threads that are doing independent
     * things. Instead, punish the case where more than one thread tries to
     * lazy-init the same 'pmont', by having each do the lazy-init math work
     * independently and only use the one from the thread that wins the race
     * (the losers throw away the work they've done).
     */
    ret = BN_MONT_CTX_new();
    if (ret == NULL)
        return NULL;
    if (!BN_MONT_CTX_set(ret, mod, ctx)) {
        BN_MONT_CTX_free(ret);
        return NULL;
    }

    /* The locked compare-and-set, after the local work is done. */
    if (*pmont) {
        BN_MONT_CTX_free(ret);
        ret = *pmont;
    } else
        *pmont = ret;
    return ret;
}


static int rsa_ossl_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    BIGNUM *r1, *m1, *vrfy, *r2, *m[RSA_MAX_PRIME_NUM - 2];
    int ret = 0, i, ex_primes = 0, smooth = 0;

    BN_CTX_start(ctx);

    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);
    m1 = BN_CTX_get(ctx);
    vrfy = BN_CTX_get(ctx);
    if (vrfy == NULL)
        goto err;

    if (rsa->flags & RSA_FLAG_CACHE_PRIVATE) {
        BIGNUM *factor = BN_new();

        if (factor == NULL)
            goto err;

/*
 * Make sure BN_mod_inverse in Montgomery initialization uses the
 * BN_FLG_CONSTTIME flag
 */
        if (!(BN_with_flags(factor, rsa->p, BN_FLG_CONSTTIME),
                BN_MONT_CTX_set_locked(&rsa->_method_mod_p, NULL,
                                       factor, ctx))
            || !(BN_with_flags(factor, rsa->q, BN_FLG_CONSTTIME),
                BN_MONT_CTX_set_locked(&rsa->_method_mod_q, NULL,
                                       factor, ctx))) {
            BN_free(factor);
            goto err;
        }

        BN_free(factor);

        smooth = (ex_primes == 0)
                 && (BN_num_bits(rsa->q) == BN_num_bits(rsa->p));
    }

    if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
        if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, NULL,
                                    rsa->n, ctx))
            goto err;

    /* compute I mod q */
    {
        BIGNUM *c = BN_new();
        if (c == NULL)
            goto err;
        BN_with_flags(c, I, BN_FLG_CONSTTIME);

        if (!BN_mod(r1, c, rsa->q, ctx)) {
            BN_free(c);
            goto err;
        }

        {
            BIGNUM *dmq1 = BN_new();
            if (dmq1 == NULL) {
                BN_free(c);
                goto err;
            }
            BN_with_flags(dmq1, rsa->dmq1, BN_FLG_CONSTTIME);

            /* compute r1^dmq1 mod q */
            if (!BN_mod_exp_mont(m1, r1, dmq1, rsa->q, ctx,
                                       rsa->_method_mod_q)) {
                BN_free(c);
                BN_free(dmq1);
                goto err;
            }
            /* We MUST free dmq1 before any further use of rsa->dmq1 */
            BN_free(dmq1);
        }

        /* compute I mod p */
        if (!BN_mod(r1, c, rsa->p, ctx)) {
            BN_free(c);
            goto err;
        }
        /* We MUST free c before any further use of I */
        BN_free(c);
    }

    {
        BIGNUM *dmp1 = BN_new();
        if (dmp1 == NULL)
            goto err;
        BN_with_flags(dmp1, rsa->dmp1, BN_FLG_CONSTTIME);

        /* compute r1^dmp1 mod p */
        if (!BN_mod_exp_mont(r0, r1, dmp1, rsa->p, ctx,
                                   rsa->_method_mod_p)) {
            BN_free(dmp1);
            goto err;
        }
        /* We MUST free dmp1 before any further use of rsa->dmp1 */
        BN_free(dmp1);
    }


    if (!BN_sub(r0, r0, m1))
        goto err;

    if (BN_is_negative(r0))
        if (!BN_add(r0, r0, rsa->p))
            goto err;

    if (!BN_mul(r1, r0, rsa->iqmp, ctx))
        goto err;

    {
        BIGNUM *pr1 = BN_new();
        if (pr1 == NULL)
            goto err;
        BN_with_flags(pr1, r1, BN_FLG_CONSTTIME);

        if (!BN_mod(r0, pr1, rsa->p, ctx)) {
            BN_free(pr1);
            goto err;
        }

        BN_free(pr1);
    }

    if (BN_is_negative(r0))
        if (!BN_add(r0, r0, rsa->p))
            goto err;
    if (!BN_mul(r1, r0, rsa->q, ctx))
        goto err;
    if (!BN_add(r0, r1, m1))
        goto err;


    tail:
    if (rsa->e && rsa->n) {
        if (1) {
            if (!BN_mod_exp_mont(vrfy, r0, rsa->e, rsa->n, ctx,
                                 rsa->_method_mod_n))
                goto err;
        } else {
            bn_correct_top(r0);
            if (!BN_mod_exp_mont(vrfy, r0, rsa->e, rsa->n, ctx,
                                       rsa->_method_mod_n))
                goto err;
        }

        if (!BN_sub(vrfy, vrfy, I))
            goto err;
        if (BN_is_zero(vrfy)) {
            bn_correct_top(r0);
            ret = 1;
            goto err;   /* not actually error */
        }
        if (!BN_mod(vrfy, vrfy, rsa->n, ctx))
            goto err;
        if (BN_is_negative(vrfy))
            if (!BN_add(vrfy, vrfy, rsa->n))
                goto err;
        if (!BN_is_zero(vrfy)) {
            BIGNUM *d = BN_new();
            if (d == NULL)
                goto err;
            BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);

            if (!BN_mod_exp_mont(r0, I, d, rsa->n, ctx,
                                       rsa->_method_mod_n)) {
                BN_free(d);
                goto err;
            }

            BN_free(d);
        }
    }

    bn_correct_top(r0);
    ret = 1;
    err:
    BN_CTX_end(ctx);
    return ret;
}


int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b,
                          BN_CTX *ctx)
{
    int ret;


    if (r == NULL && (r = b->Ai) == NULL) {
        eosio_assert(false, (char *)"BN_F_BN_BLINDING_INVERT_EX, BN_R_NOT_INITIALIZED");
        return 0;
    }

    if (b->m_ctx != NULL) {
        /* ensure that BN_mod_mul_montgomery takes pre-defined path */
        if (n->dmax >= r->top) {
            size_t i, rtop = r->top, ntop = n->top;
            BN_ULONG mask;

            for (i = 0; i < rtop; i++) {
                mask = (BN_ULONG)0 - ((i - ntop) >> (8 * sizeof(i) - 1));
                n->d[i] &= mask;
            }
            mask = (BN_ULONG)0 - ((rtop - ntop) >> (8 * sizeof(ntop) - 1));
            /* always true, if (rtop >= ntop) n->top = r->top; */
            n->top = (int)(rtop & ~mask) | (ntop & mask);
            n->flags |= (BN_FLG_FIXED_TOP & ~mask);
        }
        ret = BN_mod_mul_montgomery(n, n, r, b->m_ctx, ctx);
    } else {
        ret = BN_mod_mul(n, n, r, b->mod, ctx);
    }

    return ret;
}

static int rsa_blinding_invert(BN_BLINDING *b, BIGNUM *f, BIGNUM *unblind,
                               BN_CTX *ctx)
{
    return BN_BLINDING_invert_ex(f, unblind, b, ctx);
}


static int bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    int n;
    size_t i, lasti, j, atop, mask;
    BN_ULONG l;

    n = BN_num_bytes(a);
    if (tolen == -1) {
        tolen = n;
    } else if (tolen < n) {     /* uncommon/unlike case */
        BIGNUM temp = *a;

        bn_correct_top(&temp);
        n = BN_num_bytes(&temp);
        if (tolen < n)
            return -1;
    }

    /* Swipe through whole available data and don't give away padded zero. */
    atop = a->dmax * BN_BYTES;
    if (atop == 0) {
        OPENSSL_cleanse(to, tolen);
        return tolen;
    }

    lasti = atop - 1;
    atop = a->top * BN_BYTES;
    for (i = 0, j = 0, to += tolen; j < (size_t)tolen; j++) {
        l = a->d[i / BN_BYTES];
        mask = 0 - ((j - atop) >> (8 * sizeof(i) - 1));
        *--to = (unsigned char)(l >> (8 * (i % BN_BYTES)) & mask);
        i += (i - lasti) >> (8 * sizeof(i) - 1); /* stay on last limb */
    }

    return tolen;
}


int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    if (tolen < 0)
        return -1;
    return bn2binpad(a, to, tolen);
}


static  unsigned int constant_time_lt(unsigned int a,
                                                 unsigned int b)
{
    return constant_time_msb(a ^ ((a ^ b) | ((a - b) ^ b)));
}

static  unsigned int constant_time_ge(unsigned int a,
                                                 unsigned int b)
{
    return ~constant_time_lt(a, b);
}

static unsigned int constant_time_select(unsigned int mask,
                                                     unsigned int a,
                                                     unsigned int b)
{
    return (mask & a) | (~mask & b);
}

static  int constant_time_select_int(unsigned int mask, int a,
                                                int b)
{
    return (int)constant_time_select(mask, (unsigned)(a), (unsigned)(b));
}

int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
                                   const unsigned char *from, int flen,
                                   int num)
{
    int i;
    /* |em| is the encoded message, zero-padded to exactly |num| bytes */
    unsigned char *em = NULL;
    unsigned int good, found_zero_byte;
    int zero_index = 0, msg_index, mlen = -1;

    if (tlen < 0 || flen < 0)
        return -1;


    if (flen > num)
        goto err;

    if (num < 11)
        goto err;

    if (flen != num) {
        em = (unsigned char *)CRYPTO_zalloc(num);
        if (em == NULL) {
            eosio_assert(false, (char *)"RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2, ERR_R_MALLOC_FAILURE");
            return -1;
        }

        memcpy(em + num - flen, from, flen);
        from = em;
    }

    good = constant_time_is_zero(from[0]);
    good &= constant_time_eq(from[1], 2);

    found_zero_byte = 0;
    for (i = 2; i < num; i++) {
        unsigned int equals0 = constant_time_is_zero(from[i]);
        zero_index =
                constant_time_select_int(~found_zero_byte & equals0, i,
                                         zero_index);
        found_zero_byte |= equals0;
    }

    good &= constant_time_ge((unsigned int)(zero_index), 2 + 8);
    msg_index = zero_index + 1;
    mlen = num - msg_index;

    /*
     * For good measure, do this check in constant time as well; it could
     * leak something if |tlen| was assuming valid padding.
     */
    good &= constant_time_ge((unsigned int)(tlen), (unsigned int)(mlen));

    /*
     * We can't continue in constant-time because we need to copy the result
     * and we cannot fake its length. This unavoidably leaks timing
     * information at the API boundary.
     */
    if (!good) {
        mlen = -1;
        goto err;
    }

    memcpy(to, from + msg_index, mlen);

    err:
    CRYPTO_clear_free(em, num);
    if (mlen == -1)
        eosio_assert(false, (char *)"RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2,RSA_R_PKCS_DECODING_ERROR");
    return mlen;
}


static BIGNUM *rsa_get_public_exp(const BIGNUM *d, const BIGNUM *p,
                                  const BIGNUM *q, BN_CTX *ctx)
{
    BIGNUM *ret = NULL, *r0, *r1, *r2;

    if (d == NULL || p == NULL || q == NULL)
        return NULL;

    BN_CTX_start(ctx);
    r0 = BN_CTX_get(ctx);
    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);
    if (r2 == NULL)
        goto err;

    if (!BN_sub(r1, p, BN_value_one()))
        goto err;
    if (!BN_sub(r2, q, BN_value_one()))
        goto err;
    if (!BN_mul(r0, r1, r2, ctx))
        goto err;

    ret = BN_mod_inverse(NULL, d, r0, ctx);
    err:
    BN_CTX_end(ctx);
    return ret;
}

int BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                     BN_CTX *ctx)
{
    return BN_mod_mul_montgomery(r, a, &(mont->RR), mont, ctx);
}

#define BN_MOD_MUL_WORD(r, w, m) \
                (BN_mul_word(r, (w)) && \
                (/* BN_ucmp(r, (m)) < 0 ? 1 :*/  \
                        (BN_mod(t, r, m, ctx) && (swap_tmp = r, r = t, t = swap_tmp, 1))))
#define BN_TO_MONTGOMERY_WORD(r, w, mont) \
                (BN_set_word(r, (w)) && BN_to_montgomery(r, r, (mont), ctx))


int BN_mod_exp_mont_word(BIGNUM *rr, BN_ULONG a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    BN_MONT_CTX *mont = NULL;
    int b, bits, ret = 0;
    int r_is_one;
    BN_ULONG w, next_w;
    BIGNUM *r, *t;
    BIGNUM *swap_tmp;

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
        || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        eosio_assert(false, (char *)"BN_F_BN_MOD_EXP_MONT_WORD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED");
        return 0;
    }


    if (!BN_is_odd(m)) {
        eosio_assert(false, (char *)"BN_F_BN_MOD_EXP_MONT_WORD, BN_R_CALLED_WITH_EVEN_MODULUS");
        return 0;
    }
    if (m->top == 1)
        a %= m->d[0];           /* make sure that 'a' is reduced */

    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }
    if (a == 0) {
        BN_zero(rr);
        ret = 1;
        return ret;
    }

    BN_CTX_start(ctx);
    r = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    if (t == NULL)
        goto err;

    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    r_is_one = 1;               /* except for Montgomery factor */

    /* bits-1 >= 0 */

    /* The result is accumulated in the product r*w. */
    w = a;                      /* bit 'bits-1' of 'p' is always set */
    for (b = bits - 2; b >= 0; b--) {
        /* First, square r*w. */
        next_w = w * w;
        if ((next_w / w) != w) { /* overflow */
            if (r_is_one) {
                if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                    goto err;
                r_is_one = 0;
            } else {
                if (!BN_MOD_MUL_WORD(r, w, m))
                    goto err;
            }
            next_w = 1;
        }
        w = next_w;
        if (!r_is_one) {
            if (!BN_mod_mul_montgomery(r, r, r, mont, ctx))
                goto err;
        }

        /* Second, multiply r*w by 'a' if exponent bit is set. */
        if (BN_is_bit_set(p, b)) {
            next_w = w * a;
            if ((next_w / a) != w) { /* overflow */
                if (r_is_one) {
                    if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                        goto err;
                    r_is_one = 0;
                } else {
                    if (!BN_MOD_MUL_WORD(r, w, m))
                        goto err;
                }
                next_w = a;
            }
            w = next_w;
        }
    }

    /* Finally, set r:=r*w. */
    if (w != 1) {
        if (r_is_one) {
            if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                goto err;
            r_is_one = 0;
        } else {
            if (!BN_MOD_MUL_WORD(r, w, m))
                goto err;
        }
    }

    if (r_is_one) {             /* can happen only if a == 1 */
        if (!BN_one(rr))
            goto err;
    } else {
        if (!BN_from_montgomery(rr, r, mont, ctx))
            goto err;
    }
    ret = 1;
    err:
    if (in_mont == NULL)
        BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    return ret;
}

struct bn_recp_ctx_st {
    BIGNUM N;                   /* the divisor */
    BIGNUM Nr;                  /* the reciprocal */
    int num_bits;
    int shift;
    int flags;
};
typedef struct bn_recp_ctx_st BN_RECP_CTX;
int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *d, BN_CTX *ctx)
{
    if (!BN_copy(&(recp->N), d))
        return 0;
    BN_zero(&(recp->Nr));
    recp->num_bits = BN_num_bits(d);
    recp->shift = 0;
    return 1;
}


void BN_RECP_CTX_init(BN_RECP_CTX *recp)
{
    memset(recp, 0, sizeof(*recp));
    bn_init(&(recp->N));
    bn_init(&(recp->Nr));
}


int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx)
{
    int ret = -1;
    BIGNUM *t;

    BN_CTX_start(ctx);
    if ((t = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (!BN_set_bit(t, len))
        goto err;

    if (!BN_div(r, NULL, t, m, ctx))
        goto err;

    ret = len;
    err:
    BN_CTX_end(ctx);
    return ret;
}

int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
                BN_RECP_CTX *recp, BN_CTX *ctx)
{
    int i, j, ret = 0;
    BIGNUM *a, *b, *d, *r;

    BN_CTX_start(ctx);
    d = (dv != NULL) ? dv : BN_CTX_get(ctx);
    r = (rem != NULL) ? rem : BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    if (b == NULL)
        goto err;

    if (BN_ucmp(m, &(recp->N)) < 0) {
        BN_zero(d);
        if (!BN_copy(r, m)) {
            BN_CTX_end(ctx);
            return 0;
        }
        BN_CTX_end(ctx);
        return 1;
    }

    i = BN_num_bits(m);
    j = recp->num_bits << 1;
    if (j > i)
        i = j;

    /* Nr := round(2^i / N) */
    if (i != recp->shift)
        recp->shift = BN_reciprocal(&(recp->Nr), &(recp->N), i, ctx);
    /* BN_reciprocal could have returned -1 for an error */
    if (recp->shift == -1)
        goto err;

    if (!BN_rshift(a, m, recp->num_bits))
        goto err;
    if (!BN_mul(b, a, &(recp->Nr), ctx))
        goto err;
    if (!BN_rshift(d, b, i - recp->num_bits))
        goto err;
    d->neg = 0;

    if (!BN_mul(b, &(recp->N), d, ctx))
        goto err;
    if (!BN_usub(r, m, b))
        goto err;
    r->neg = 0;

    j = 0;
    while (BN_ucmp(r, &(recp->N)) >= 0) {
        if (j++ > 2) {
            goto err;
        }
        if (!BN_usub(r, r, &(recp->N)))
            goto err;
        if (!BN_add_word(d, 1))
            goto err;
    }

    r->neg = BN_is_zero(r) ? 0 : m->neg;
    d->neg = m->neg ^ recp->N.neg;
    ret = 1;
    err:
    BN_CTX_end(ctx);
    return ret;
}

int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
                          BN_RECP_CTX *recp, BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *a;
    const BIGNUM *ca;

    BN_CTX_start(ctx);
    if ((a = BN_CTX_get(ctx)) == NULL)
        goto err;
    if (y != NULL) {
        if (x == y) {
            if (!BN_sqr(a, x, ctx))
                goto err;
        } else {
            if (!BN_mul(a, x, y, ctx))
                goto err;
        }
        ca = a;
    } else
        ca = x;                 /* Just do the mod */

    ret = BN_div_recp(NULL, r, ca, recp, ctx);
    err:
    BN_CTX_end(ctx);
    return ret;
}

void BN_RECP_CTX_free(BN_RECP_CTX *recp)
{
    if (recp == NULL)
        return;
    BN_free(&recp->N);
    BN_free(&recp->Nr);
    if (recp->flags & BN_FLG_MALLOCED)
        CRYPTO_free(recp);
}

int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx)
{
    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *aa;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];
    BN_RECP_CTX recp;

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
        || BN_get_flags(a, BN_FLG_CONSTTIME) != 0
        || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        eosio_assert(false, (char *)"BN_F_BN_MOD_EXP_RECP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED");
        return 0;
    }

    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(r);
        } else {
            ret = BN_one(r);
        }
        return ret;
    }

    BN_CTX_start(ctx);
    aa = BN_CTX_get(ctx);
    val[0] = BN_CTX_get(ctx);
    if (val[0] == NULL)
        goto err;

    BN_RECP_CTX_init(&recp);
    if (m->neg) {
        /* ignore sign of 'm' */
        if (!BN_copy(aa, m))
            goto err;
        aa->neg = 0;
        if (BN_RECP_CTX_set(&recp, aa, ctx) <= 0)
            goto err;
    } else {
        if (BN_RECP_CTX_set(&recp, m, ctx) <= 0)
            goto err;
    }

    if (!BN_nnmod(val[0], a, m, ctx))
        goto err;               /* 1 */
    if (BN_is_zero(val[0])) {
        BN_zero(r);
        ret = 1;
        goto err;
    }

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!BN_mod_mul_reciprocal(aa, val[0], val[0], &recp, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
                !BN_mod_mul_reciprocal(val[i], val[i - 1], aa, &recp, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

    if (!BN_one(r))
        goto err;

    for (;;) {
        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start)
                if (!BN_mod_mul_reciprocal(r, r, r, &recp, ctx))
                    goto err;
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!BN_mod_mul_reciprocal(r, r, r, &recp, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!BN_mod_mul_reciprocal(r, r, val[wvalue >> 1], &recp, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }
    ret = 1;
    err:
    BN_CTX_end(ctx);
    BN_RECP_CTX_free(&recp);
    return ret;
}


int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
               BN_CTX *ctx)
{
    int ret;
#define MONT_MUL_MOD
#define MONT_EXP_WORD
#define RECP_MUL_MOD

#ifdef MONT_MUL_MOD
    if (BN_is_odd(m)) {
# ifdef MONT_EXP_WORD
        if (a->top == 1 && !a->neg
            && (BN_get_flags(p, BN_FLG_CONSTTIME) == 0)
            && (BN_get_flags(a, BN_FLG_CONSTTIME) == 0)
            && (BN_get_flags(m, BN_FLG_CONSTTIME) == 0)) {
            BN_ULONG A = a->d[0];
            ret = BN_mod_exp_mont_word(r, A, p, m, ctx, NULL);
        } else
# endif
            ret = BN_mod_exp_mont(r, a, p, m, ctx, NULL);
    } else
#endif
#ifdef RECP_MUL_MOD
    {
        ret = BN_mod_exp_recp(r, a, p, m, ctx);
    }
#else
    {
        ret = BN_mod_exp_simple(r, a, p, m, ctx);
    }
#endif

    return ret;
}


BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b,
                                      const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
                                      int (*bn_mod_exp) (BIGNUM *r,
                                                         const BIGNUM *a,
                                                         const BIGNUM *p,
                                                         const BIGNUM *m,
                                                         BN_CTX *ctx,
                                                         BN_MONT_CTX *m_ctx),
                                      BN_MONT_CTX *m_ctx)
{
    int retry_counter = 32;
    BN_BLINDING *ret = NULL;

    if (b == NULL)
        ret = BN_BLINDING_new(NULL, NULL, m);
    else
        ret = b;

    if (ret == NULL)
        goto err;

    if (ret->A == NULL && (ret->A = BN_new()) == NULL)
        goto err;
    if (ret->Ai == NULL && (ret->Ai = BN_new()) == NULL)
        goto err;

    if (e != NULL) {
        BN_free(ret->e);
        ret->e = BN_dup(e);
    }
    if (ret->e == NULL)
        goto err;

    if (bn_mod_exp != NULL)
        ret->bn_mod_exp = bn_mod_exp;
    if (m_ctx != NULL)
        ret->m_ctx = m_ctx;

    do {
        int rv;
        if (!BN_priv_rand_range(ret->A, ret->mod))
            goto err;
        if (int_bn_mod_inverse(ret->Ai, ret->A, ret->mod, ctx, &rv))
            break;

        if (!rv)
            goto err;

        if (retry_counter-- == 0) {
            goto err;
        }
    } while (1);

    if (ret->bn_mod_exp != NULL && ret->m_ctx != NULL) {
        if (!ret->bn_mod_exp(ret->A, ret->A, ret->e, ret->mod, ctx, ret->m_ctx))
            goto err;
    } else {
        if (!BN_mod_exp(ret->A, ret->A, ret->e, ret->mod, ctx))
            goto err;
    }

    if (ret->m_ctx != NULL) {
        if (!bn_to_mont_fixed_top(ret->Ai, ret->Ai, ret->m_ctx, ctx)
            || !bn_to_mont_fixed_top(ret->A, ret->A, ret->m_ctx, ctx))
            goto err;
    }

    return ret;
    err:
    if (b == NULL) {
        BN_BLINDING_free(ret);
        ret = NULL;
    }

    return ret;
}

int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx)
{
    int ret = 0;

    if ((b->A == NULL) || (b->Ai == NULL)) {
        goto err;
    }

    if (b->counter == -1)
        b->counter = 0;

    if (++b->counter == BN_BLINDING_COUNTER && b->e != NULL &&
        !(b->flags & BN_BLINDING_NO_RECREATE)) {
        if (!BN_BLINDING_create_param(b, NULL, NULL, ctx, NULL, NULL))
            goto err;
    } else if (!(b->flags & BN_BLINDING_NO_UPDATE)) {
        if (b->m_ctx != NULL) {
            if (!bn_mul_mont_fixed_top(b->Ai, b->Ai, b->Ai, b->m_ctx, ctx)
                || !bn_mul_mont_fixed_top(b->A, b->A, b->A, b->m_ctx, ctx))
                goto err;
        } else {
            if (!BN_mod_mul(b->Ai, b->Ai, b->Ai, b->mod, ctx)
                || !BN_mod_mul(b->A, b->A, b->A, b->mod, ctx))
                goto err;
        }
    }

    ret = 1;
    err:
    if (b->counter == BN_BLINDING_COUNTER)
        b->counter = 0;
    eosio_assert(false, (char *)"BN_BLINDING_update error");
    return ret;
}

BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *in_ctx)
{
    BIGNUM *e;
    BN_CTX *ctx;
    BN_BLINDING *ret = NULL;

    if (in_ctx == NULL) {
        if ((ctx = BN_CTX_new()) == NULL)
            return 0;
    } else {
        ctx = in_ctx;
    }

    BN_CTX_start(ctx);
    e = BN_CTX_get(ctx);
    if (e == NULL) {
        goto err;
    }

    if (rsa->e == NULL) {
        e = rsa_get_public_exp(rsa->d, rsa->p, rsa->q, ctx);
        if (e == NULL) {
            goto err;
        }
    } else {
        e = rsa->e;
    }

    {
        BIGNUM *n = BN_new();

        if (n == NULL) {
            goto err;
        }
        BN_with_flags(n, rsa->n, BN_FLG_CONSTTIME);

        ret = BN_BLINDING_create_param(NULL, e, n, ctx, BN_mod_exp_mont,
                                       rsa->_method_mod_n);
        /* We MUST free n before any further use of rsa->n */
        BN_free(n);
    }
    if (ret == NULL) {
        goto err;
    }

    err:
    BN_CTX_end(ctx);
    if (ctx != in_ctx)
        BN_CTX_free(ctx);
    if (e != rsa->e)
        BN_free(e);

    return ret;
}


static BN_BLINDING *rsa_get_blinding(RSA *rsa, int *local, BN_CTX *ctx)
{
    BN_BLINDING *ret;

    if (rsa->blinding == NULL) {
        rsa->blinding = RSA_setup_blinding(rsa, ctx);
    }

    ret = rsa->blinding;
    if (ret == NULL)
        goto err;


    *local = 1;
    return ret;

    err:
    eosio_assert(false, (char *)"rsa_get_blinding");
    return ret;
}




# define RSA_FLAG_EXT_PKEY               0x0020
# define RSA_ASN1_VERSION_MULTI          1
# define RSA_PKCS1_PADDING       1
static int rsa_ossl_private_decrypt(int flen, const unsigned char *from,
                                    unsigned char *to, RSA *rsa, int padding)
{
    BIGNUM *f, *ret;
    int j, num = 0, r = -1;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;
    int local_blinding = 0;
    BIGNUM *unblind = NULL;
    BN_BLINDING *blinding = NULL;

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = (unsigned char *)CRYPTO_malloc(num);
    if(ret == NULL || buf == NULL){
        goto err;
    }

    if(flen > num){
        goto err;
    }

    /* make data into a big number */
    if(BN_bin2bn(from, (int)flen, f) == NULL){
        goto err;
    }
    if(BN_ucmp(f, rsa->n) >= 0){
        goto err;
    }

    if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
        blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
        if(blinding == NULL){
            goto err;
        }
    }

    if (blinding != NULL) {
        if (local_blinding == 0 && ((unblind = BN_CTX_get(ctx)) == NULL)) {
            goto err;
        }

        if(!rsa_blinding_convert(blinding, f, unblind, ctx)){
            goto err;
        }
    }

    /* do the decrypt */
    if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
        (rsa->version == RSA_ASN1_VERSION_MULTI) ||
        ((rsa->p != NULL) &&
         (rsa->q != NULL) &&
         (rsa->dmp1 != NULL) && (rsa->dmq1 != NULL) && (rsa->iqmp != NULL))) {
        if (!rsa_ossl_mod_exp(ret, f, rsa, ctx))
            goto err;
    } else {
        BIGNUM *d = BN_new();
        if(d == NULL){
            goto err;
        }
        BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
        /* We MUST free d before any further use of rsa->d */
        if (!BN_mod_exp_mont(ret, f, d, rsa->n, ctx,
                                   rsa->_method_mod_n)) {
            BN_free(d);
            goto err;
        }
        BN_free(d);
    }

    if (blinding)
        if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
            goto err;

    j = BN_bn2binpad(ret, buf, num);

    switch (padding) {
        case RSA_PKCS1_PADDING:
            r = RSA_padding_check_PKCS1_type_2(to, num, buf, j, num);
            break;
        default:
            goto err;
    }

    if (r < 0)
        goto err;

err:
    if (ctx != NULL)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    CRYPTO_clear_free(buf, num);
    return r;
}



static int rsa_ossl_init(RSA *rsa)
{
    rsa->flags |= RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE;
    return 1;
}





static RSA_METHOD rsa_pkcs1_ossl_meth = {
        (char *)"OpenSSL PKCS#1 RSA",
        rsa_ossl_private_decrypt,
        rsa_ossl_init,
        RSA_FLAG_FIPS_METHOD,       /* flags */
        NULL,
};



static const RSA_METHOD *default_RSA_meth = &rsa_pkcs1_ossl_meth;

const RSA_METHOD *RSA_get_default_method(void)
{
    return default_RSA_meth;
}





void RSA_free(RSA *r)
{
    int i;

    if (r == NULL)
        return;

    BN_free(r->n);
    BN_free(r->e);
    BN_clear_free(r->d);
    BN_clear_free(r->p);
    BN_clear_free(r->q);
    BN_clear_free(r->dmp1);
    BN_clear_free(r->dmq1);
    BN_clear_free(r->iqmp);
    BN_BLINDING_free(r->blinding);
    BN_BLINDING_free(r->mt_blinding);
    CRYPTO_free(r->bignum_data);
    CRYPTO_free(r);
}

static ENGINE_TABLE *rsa_table = NULL;

/* Obtains an RSA implementation from an ENGINE functional reference */
const RSA_METHOD *ENGINE_get_RSA(const ENGINE *e)
{
    return e->rsa_meth;
}


# define CRYPTO_EX_INDEX_RSA              9
typedef void CRYPTO_EX_new (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                            int idx, long argl, void *argp);
typedef void CRYPTO_EX_free (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                             int idx, long argl, void *argp);
typedef int CRYPTO_EX_dup (CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
                           void *from_d, int idx, long argl, void *argp);
typedef struct ex_callback_st EX_CALLBACK;
struct ex_callback_st {
    long argl;                  /* Arbitrary long */
    void *argp;                 /* Arbitrary void * */
    CRYPTO_EX_new *new_func;
    CRYPTO_EX_free *free_func;
    CRYPTO_EX_dup *dup_func;
};

typedef struct ex_callbacks_st {
    STACK_OF(EX_CALLBACK) *meth;
} EX_CALLBACKS;

# define CRYPTO_EX_INDEX__COUNT          16
# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))

RSA *RSA_new_method(ENGINE *engine)
{
    RSA *ret = (RSA *)CRYPTO_zalloc(sizeof(*ret));

    if (ret == NULL) {
        eosio_assert(false, "malloc error");
        return NULL;
    }

    ret->references = 1;
    ret->meth = RSA_get_default_method();
    ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
    ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        goto err;
    }

    return ret;

err:
    RSA_free(ret);
    return NULL;
}


RSA *RSA_new(void)
{
    return RSA_new_method(NULL);
}


struct evp_pkey_st {
    int type;
    int save_type;
    CRYPTO_REF_COUNT references;
 //   const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    ENGINE *pmeth_engine; /* If not NULL public key ENGINE to use */
    union {
        void *ptr;
        struct rsa_st *rsa;     /* RSA */
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
} /* EVP_PKEY */ ;




/*********************************************************bio********************************************************/


typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;


typedef int BIO_info_cb(BIO *, int, int);
struct bio_method_st {
    int type;
    char *name;
    int (*bwrite) (BIO *, const char *, size_t, size_t *);
    int (*bwrite_old) (BIO *, const char *, int);
    int (*bread) (BIO *, char *, size_t, size_t *);
    int (*bread_old) (BIO *, char *, int);
    int (*bputs) (BIO *, const char *);
    int (*bgets) (BIO *, char *, int);
    long (*ctrl) (BIO *, int, long, void *);
    int (*create) (BIO *);
    int (*destroy) (BIO *);
    long (*callback_ctrl) (BIO *, int, BIO_info_cb *);
};

typedef long (*BIO_callback_fn)(BIO *b, int oper, const char *argp, int argi,
                                long argl, long ret);
typedef long (*BIO_callback_fn_ex)(BIO *b, int oper, const char *argp,
                                   size_t len, int argi,
                                   long argl, int ret, size_t *processed);



struct bio_st {
    const BIO_METHOD *method;
    /* bio, mode, argp, argi, argl, ret */
    BIO_callback_fn callback;
    BIO_callback_fn_ex callback_ex;
    char *cb_arg;               /* first argument for the callback */
    int init;
    int shutdown;
    int flags;                  /* extra storage */
    int retry_reason;
    int num;
    void *ptr;
    struct bio_st *next_bio;    /* used by filter BIOs */
    struct bio_st *prev_bio;    /* used by filter BIOs */
    CRYPTO_REF_COUNT references;
    uint64_t num_read;
    uint64_t num_write;
    CRYPTO_EX_DATA ex_data;
};

typedef struct buf_mem_st BUF_MEM;
struct buf_mem_st {
    size_t length;              /* current number of bytes */
    char *data;
    size_t max;                 /* size of buffer */
    unsigned long flags;
};

/* BIO memory stores buffer and read pointer  */
typedef struct bio_buf_mem_st {
    struct buf_mem_st *buf;   /* allocated buffer */
    struct buf_mem_st *readp; /* read pointer */
} BIO_BUF_MEM;


# define BIO_TYPE_SOURCE_SINK    0x0400
# define BIO_TYPE_MEM            ( 1|BIO_TYPE_SOURCE_SINK)


BUF_MEM *BUF_MEM_new(void)
{
    BUF_MEM *ret;

    ret = (BUF_MEM *)CRYPTO_zalloc(sizeof(*ret));
    if (ret == NULL) {
        eosio_assert(false, "BUF_F_BUF_MEM_NEW, ERR_R_MALLOC_FAILURE");
        return NULL;
    }
    return ret;
}

BUF_MEM *BUF_MEM_new_ex(unsigned long flags)
{
    BUF_MEM *ret;

    ret = BUF_MEM_new();
    if (ret != NULL)
        ret->flags = flags;
    return ret;
}


# define BUF_MEM_FLAG_SECURE  0x01
void BUF_MEM_free(BUF_MEM *a)
{
    if (a == NULL)
        return;
    if (a->data != NULL) {
        if (a->flags & BUF_MEM_FLAG_SECURE)
            CRYPTO_clear_free(a->data, a->max);
        else
            CRYPTO_clear_free(a->data, a->max);
    }

    CRYPTO_free(a);
}


static int mem_init(BIO *bi, unsigned long flags)
{
    BIO_BUF_MEM *bb = (BIO_BUF_MEM *)CRYPTO_zalloc(sizeof(*bb));

    if (bb == NULL)
        return 0;
    if ((bb->buf = BUF_MEM_new_ex(flags)) == NULL) {
        CRYPTO_free(bb);
        return 0;
    }
    if ((bb->readp = (BUF_MEM *)CRYPTO_zalloc(sizeof(*bb->readp))) == NULL) {
        BUF_MEM_free(bb->buf);
        CRYPTO_free(bb);
        return 0;
    }
    *bb->readp = *bb->buf;
    bi->shutdown = 1;
    bi->init = 1;
    bi->num = -1;
    bi->ptr = (char *)bb;
    return 1;
}

static int mem_new(BIO *bi)
{
    return mem_init(bi, 0L);
}

static int secmem_new(BIO *bi)
{
    return mem_init(bi, BUF_MEM_FLAG_SECURE);
}


void BIO_clear_flags(BIO *b, int flags)
{
    b->flags &= ~flags;
}

void BIO_set_flags(BIO *b, int flags)
{
    b->flags |= flags;
}

# define BIO_FLAGS_READ          0x01
# define BIO_FLAGS_WRITE         0x02
# define BIO_FLAGS_IO_SPECIAL    0x04
# define BIO_FLAGS_RWS (BIO_FLAGS_READ|BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL)
# define BIO_FLAGS_SHOULD_RETRY  0x08
# define BIO_clear_retry_flags(b) \
                BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
# define BIO_set_retry_read(b) \
                BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))

static int mem_read(BIO *b, char *out, int outl)
{
    int ret = -1;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;
    BUF_MEM *bm = bbm->readp;

    BIO_clear_retry_flags(b);
    ret = (outl >= 0 && (size_t)outl > bm->length) ? (int)bm->length : outl;
    if ((out != NULL) && (ret > 0)) {
        memcpy(out, bm->data, ret);
        bm->length -= ret;
        bm->data += ret;
    } else if (bm->length == 0) {
        ret = b->num;
        if (ret != 0)
            BIO_set_retry_read(b);
    }
    return ret;
}


static int mem_gets(BIO *bp, char *buf, int size)
{
    int i, j;
    int ret = -1;
    char *p;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)bp->ptr;
    BUF_MEM *bm = bbm->readp;

    BIO_clear_retry_flags(bp);
    j = bm->length;
    if ((size - 1) < j)
        j = size - 1;
    if (j <= 0) {
        *buf = '\0';
        return 0;
    }
    p = bm->data;
    for (i = 0; i < j; i++) {
        if (p[i] == '\n') {
            i++;
            break;
        }
    }

    /*
     * i is now the max num of bytes to copy, either j or up to
     * and including the first newline
     */

    i = mem_read(bp, buf, i);
    if (i > 0)
        buf[i] = '\0';
    ret = i;
    return ret;
}

#define LIMIT_BEFORE_EXPANSION 0x5ffffffc

static char *sec_alloc_realloc(BUF_MEM *str, size_t len)
{
    char *ret;

    ret = (char *)CRYPTO_malloc(len);
    if (str->data != NULL) {
        if (ret != NULL) {
            memcpy(ret, str->data, str->length);
            CRYPTO_clear_free(str->data, str->length);
            str->data = NULL;
        }
    }
    return ret;
}

void *CRYPTO_clear_realloc(void *str, size_t old_len, size_t num)
{
    void *ret = NULL;

    if (str == NULL)
        return CRYPTO_malloc(num);

    if (num == 0) {
        CRYPTO_clear_free(str, old_len);
        return NULL;
    }

    /* Can't shrink the buffer since memcpy below copies |old_len| bytes. */
    if (num < old_len) {
        OPENSSL_cleanse((char*)str + num, old_len - num);
        return str;
    }

    ret = CRYPTO_malloc(num);
    if (ret != NULL) {
        memcpy(ret, str, old_len);
        CRYPTO_clear_free(str, old_len);
    }
    return ret;
}


size_t BUF_MEM_grow_clean(BUF_MEM *str, size_t len)
{
    char *ret;
    size_t n;

    if (str->length >= len) {
        if (str->data != NULL)
            memset(&str->data[len], 0, str->length - len);
        str->length = len;
        return len;
    }
    if (str->max >= len) {
        memset(&str->data[str->length], 0, len - str->length);
        str->length = len;
        return len;
    }
    /* This limit is sufficient to ensure (len+3)/3*4 < 2**31 */
    if (len > LIMIT_BEFORE_EXPANSION) {
        eosio_assert(false, "BUF_F_BUF_MEM_GROW_CLEAN, ERR_R_MALLOC_FAILURE");
        return 0;
    }
    n = (len + 3) / 3 * 4;
    if ((str->flags & BUF_MEM_FLAG_SECURE))
        ret = sec_alloc_realloc(str, n);
    else
        ret = (char *)CRYPTO_clear_realloc(str->data, str->max, n);
    if (ret == NULL) {
        eosio_assert(false, "BUF_F_BUF_MEM_GROW_CLEAN, ERR_R_MALLOC_FAILURE");
        len = 0;
    } else {
        str->data = ret;
        str->max = n;
        memset(&str->data[str->length], 0, len - str->length);
        str->length = len;
    }
    return len;
}

static int mem_buf_sync(BIO *b)
{
    if (b != NULL && b->init != 0 && b->ptr != NULL) {
        BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;

        if (bbm->readp->data != bbm->buf->data) {
            memmove(bbm->buf->data, bbm->readp->data, bbm->readp->length);
            bbm->buf->length = bbm->readp->length;
            bbm->readp->data = bbm->buf->data;
        }
    }
    return 0;
}

# define BIO_FLAGS_MEM_RDONLY    0x200
static int mem_write(BIO *b, const char *in, int inl)
{
    int ret = -1;
    int blen;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;

    if (in == NULL) {
        goto end;
    }
    if (b->flags & BIO_FLAGS_MEM_RDONLY) {
        goto end;
    }
    BIO_clear_retry_flags(b);
    if (inl == 0)
        return 0;
    blen = bbm->readp->length;
    mem_buf_sync(b);
    if (BUF_MEM_grow_clean(bbm->buf, blen + inl) == 0)
        goto end;
    memcpy(bbm->buf->data + blen, in, inl);
    *bbm->readp = *bbm->buf;
    ret = inl;
    end:
    return ret;
}

static int mem_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = mem_write(bp, str, n);
    /* memory semantics is that it will always work */
    return ret;
}



static int mem_buf_free(BIO *a, int free_all)
{
    if (a == NULL)
        return 0;

    if (a->shutdown && a->init && a->ptr != NULL) {
        BIO_BUF_MEM *bb = (BIO_BUF_MEM *)a->ptr;
        BUF_MEM *b = bb->buf;

        if (a->flags & BIO_FLAGS_MEM_RDONLY)
            b->data = NULL;
        BUF_MEM_free(b);
        if (free_all) {
            CRYPTO_free(bb->readp);
            CRYPTO_free(bb);
        }
        a->ptr = NULL;
    }
    return 1;
}

static int mem_free(BIO *a)
{
    return mem_buf_free(a, 1);
}


static long mem_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    char **pptr;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)b->ptr;
    BUF_MEM *bm;

    switch (cmd) {
        case BIO_CTRL_RESET:
            bm = bbm->buf;
            if (bm->data != NULL) {
                /* For read only case reset to the start again */
                if ((b->flags & BIO_FLAGS_MEM_RDONLY) || (b->flags & BIO_FLAGS_NONCLEAR_RST)) {
                    bm->length = bm->max;
                } else {
                    memset(bm->data, 0, bm->max);
                    bm->length = 0;
                }
                *bbm->readp = *bbm->buf;
            }
            break;
        case BIO_CTRL_EOF:
            bm = bbm->readp;
            ret = (long)(bm->length == 0);
            break;
        case BIO_C_SET_BUF_MEM_EOF_RETURN:
            b->num = (int)num;
            break;
        case BIO_CTRL_INFO:
            bm = bbm->readp;
            ret = (long)bm->length;
            if (ptr != NULL) {
                pptr = (char **)ptr;
                *pptr = (char *)&(bm->data[0]);
            }
            break;
        case BIO_C_SET_BUF_MEM:
            mem_buf_free(b, 0);
            b->shutdown = (int)num;
            bbm->buf = (struct buf_mem_st *)ptr;
            *bbm->readp = *bbm->buf;
            b->ptr = bbm;
            break;
        case BIO_C_GET_BUF_MEM_PTR:
            if (ptr != NULL) {
                mem_buf_sync(b);
                bm = bbm->readp;
                pptr = (char **)ptr;
                *pptr = (char *)bm;
            }
            break;
        case BIO_CTRL_GET_CLOSE:
            ret = (long)b->shutdown;
            break;
        case BIO_CTRL_SET_CLOSE:
            b->shutdown = (int)num;
            break;
        case BIO_CTRL_WPENDING:
            ret = 0L;
            break;
        case BIO_CTRL_PENDING:
            bm = bbm->readp;
            ret = (long)bm->length;
            break;
        case BIO_CTRL_DUP:
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;
        case BIO_CTRL_PUSH:
        case BIO_CTRL_POP:
        default:
            ret = 0;
            break;
    }
    return ret;
}

int bread_conv(BIO *bio, char *data, size_t datal, size_t *readbytes)
{
    int ret;

    if (datal > INT_MAX)
        datal = INT_MAX;

    ret = bio->method->bread_old(bio, data, (int)datal);

    if (ret <= 0) {
        *readbytes = 0;
        return ret;
    }

    *readbytes = (size_t)ret;

    return 1;
}

int bwrite_conv(BIO *bio, const char *data, size_t datal, size_t *written)
{
    int ret;

    if (datal > INT_MAX)
        datal = INT_MAX;

    ret = bio->method->bwrite_old(bio, data, (int)datal);

    if (ret <= 0) {
        *written = 0;
        return ret;
    }

    *written = (size_t)ret;

    return 1;
}

static const BIO_METHOD mem_method = {
        BIO_TYPE_MEM,
        (char *)"memory buffer",
        bwrite_conv,
        mem_write,
        /* TODO: Convert to new style read function */
        bread_conv,
        mem_read,
        mem_puts,
        mem_gets,
        mem_ctrl,
        mem_new,
        mem_free,
        NULL,                      /* mem_callback_ctrl */
};


static const BIO_METHOD secmem_method = {
        BIO_TYPE_MEM,
        (char *)"secure memory buffer",
        /* TODO: Convert to new style write function */
        bwrite_conv,
        mem_write,
        /* TODO: Convert to new style read function */
        bread_conv,
        mem_read,
        mem_puts,
        mem_gets,
        mem_ctrl,
        secmem_new,
        mem_free,
        NULL,                      /* mem_callback_ctrl */
};


const BIO_METHOD *BIO_s_mem(void)
{
    return &mem_method;
}

const BIO_METHOD *BIO_s_secmem(void)
{
    return(&secmem_method);
}

# define CRYPTO_EX_INDEX_BIO             12
BIO *BIO_new(const BIO_METHOD *method)
{
    BIO *bio = (BIO *)CRYPTO_zalloc(sizeof(*bio));

    if (bio == NULL) {
        eosio_assert(false, "BIO_F_BIO_NEW, ERR_R_MALLOC_FAILURE");
        return NULL;
    }

    bio->method = method;
    bio->shutdown = 1;
    bio->references = 1;

    if (method->create != NULL && !method->create(bio)) {
        goto err;
    }

    if (method->create == NULL)
        bio->init = 1;

    return bio;

    err:
    CRYPTO_free(bio);
    eosio_assert(false, "BIO_F_BIO_NEW, ERR_R_INIT_FAIL");
    return NULL;
}



# define BIO_FLAGS_MEM_RDONLY    0x200
BIO *BIO_new_mem_buf(const void *buf, int len)
{
    BIO *ret;
    BUF_MEM *b;
    BIO_BUF_MEM *bb;
    size_t sz;

    if (buf == NULL) {
        eosio_assert(false, "BIO_F_BIO_NEW_MEM_BUF, BIO_R_NULL_PARAMETER");
        return NULL;
    }

    sz = (len < 0) ? strlen((const char *)buf) : (size_t)len;
    if ((ret = BIO_new(BIO_s_mem())) == NULL)
        return NULL;
    bb = (BIO_BUF_MEM *)ret->ptr;
    b = bb->buf;
    /* Cast away const and trust in the MEM_RDONLY flag. */
    b->data = (char *)buf;
    b->length = sz;
    b->max = sz;
    *bb->readp = *bb->buf;
    ret->flags |= BIO_FLAGS_MEM_RDONLY;
    /* Since this is static data retrying won't help */
    ret->num = 0;
    return ret;
}


typedef struct evp_cipher_info_st {
    const EVP_CIPHER *cipher;
    unsigned char iv[EVP_MAX_IV_LENGTH];
} EVP_CIPHER_INFO;


static void pem_free(void *p, unsigned int flags, size_t num)
{
    if (flags & PEM_FLAG_SECURE)
        CRYPTO_clear_free(p, num);
    else
        CRYPTO_free(p);
}

typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
typedef struct pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;
struct pkcs8_priv_key_info_st {
    ASN1_INTEGER *version;
    X509_ALGOR *pkeyalg;
    ASN1_OCTET_STRING *pkey;
    STACK_OF(X509_ATTRIBUTE) *attributes;
};
struct evp_pkey_asn1_method_st {
    int pkey_id;
    int pkey_base_id;
    unsigned long pkey_flags;
    char *pem_str;
    char *info;
    int (*priv_decode) (EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8inf);
} /* EVP_PKEY_ASN1_METHOD */ ;


int pem_check_suffix(const char *pem_str, const char *suffix)
{
    int pem_len = strlen(pem_str);
    int suffix_len = strlen(suffix);
    const char *p;
    if (suffix_len + 1 >= pem_len)
        return 0;
    p = pem_str + pem_len - suffix_len;
    if (strcmp(p, suffix))
        return 0;
    p--;
    if (*p != ' ')
        return 0;
    return p - pem_str;
}


# define PEM_STRING_EVP_PKEY     "ANY PRIVATE KEY"
# define PEM_STRING_PKCS8        "ENCRYPTED PRIVATE KEY"
# define PEM_STRING_PKCS8INF     "PRIVATE KEY"
# define ASN1_PKEY_ALIAS         0x1
typedef struct evp_Encode_Ctx_st EVP_ENCODE_CTX;
struct evp_Encode_Ctx_st {
    /* number saved in a partial encode/decode */
    int num;
    /*
     * The length is either the output line length (in input bytes) or the
     * shortest input line length that is ok.  Once decoding begins, the
     * length is adjusted up each time a longer line is decoded
     */
    int length;
    /* data to encode */
    unsigned char enc_data[80];
    /* number read on current line */
    int line_num;
    unsigned int flags;
};

EVP_ENCODE_CTX *EVP_ENCODE_CTX_new(void)
{
    return (EVP_ENCODE_CTX *)CRYPTO_zalloc(sizeof(EVP_ENCODE_CTX));
}

void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx)
{
    CRYPTO_free(ctx);
}

# define CRYPTO_DOWN_REF(val, ret, lock) CRYPTO_atomic_add(val, -1, ret, lock)
int BIO_free(BIO *a)
{
    int ret;
    if (a == NULL)
        return 0;

    if (CRYPTO_DOWN_REF(&a->references, &ret, NULL) <= 0)
        return 0;

//    if (ret > 0)
//        return 1;
//    eosio_assert(ret > 0,"ret < 0");

    if (a->callback != NULL || a->callback_ex != NULL) {
        eosio_assert(false, "a->callback");
    }

    if ((a->method != NULL) && (a->method->destroy != NULL))
        a->method->destroy(a);

    CRYPTO_free(a);
    return 1;
}


#   define PEM_FLAG_ONLY_B64           0x4




int BIO_gets(BIO *b, char *buf, int size)
{
    int ret;
    size_t readbytes = 0;

    if(b == NULL){
        eosio_assert(false,"b == NULL");
    }
    if(b->method == NULL){
        eosio_assert(false,"b->method == NULL");
    }
    if(b->method->bgets == NULL){
        eosio_assert(false,"b->method->bgets == NULL");
    }

    if(size <= 0){
        eosio_assert(false,"size <= 0");
    }



    if (!b->init) {
        eosio_assert(false,"BIO_F_BIO_GETS, BIO_R_UNINITIALIZED");
        return -2;
    }

    ret = b->method->bgets(b, buf, size);

    if (ret > 0) {
        readbytes = ret;
        ret = 1;
    }

    if (ret > 0) {
        /* Shouldn't happen */
        if (readbytes > (size_t)size)
            ret = -1;
        else
            ret = (int)readbytes;
    }

    return ret;
}

static void *pem_malloc(int num, unsigned int flags)
{
    return  CRYPTO_malloc(num);
}






# define CTYPE_MASK_lower       0x1
# define CTYPE_MASK_upper       0x2
# define CTYPE_MASK_digit       0x4
# define CTYPE_MASK_space       0x8
# define CTYPE_MASK_xdigit      0x10
# define CTYPE_MASK_blank       0x20
# define CTYPE_MASK_cntrl       0x40
# define CTYPE_MASK_graph       0x80
# define CTYPE_MASK_print       0x100
# define CTYPE_MASK_punct       0x200
# define CTYPE_MASK_base64      0x400
# define CTYPE_MASK_asn1print   0x800

static const unsigned short ctype_char_map[128] = {
        /* 00 nul */ CTYPE_MASK_cntrl,
        /* 01 soh */ CTYPE_MASK_cntrl,
        /* 02 stx */ CTYPE_MASK_cntrl,
        /* 03 etx */ CTYPE_MASK_cntrl,
        /* 04 eot */ CTYPE_MASK_cntrl,
        /* 05 enq */ CTYPE_MASK_cntrl,
        /* 06 ack */ CTYPE_MASK_cntrl,
        /* 07 \a  */ CTYPE_MASK_cntrl,
        /* 08 \b  */ CTYPE_MASK_cntrl,
        /* 09 \t  */ CTYPE_MASK_blank | CTYPE_MASK_cntrl | CTYPE_MASK_space,
        /* 0A \n  */ CTYPE_MASK_cntrl | CTYPE_MASK_space,
        /* 0B \v  */ CTYPE_MASK_cntrl | CTYPE_MASK_space,
        /* 0C \f  */ CTYPE_MASK_cntrl | CTYPE_MASK_space,
        /* 0D \r  */ CTYPE_MASK_cntrl | CTYPE_MASK_space,
        /* 0E so  */ CTYPE_MASK_cntrl,
        /* 0F si  */ CTYPE_MASK_cntrl,
        /* 10 dle */ CTYPE_MASK_cntrl,
        /* 11 dc1 */ CTYPE_MASK_cntrl,
        /* 12 dc2 */ CTYPE_MASK_cntrl,
        /* 13 dc3 */ CTYPE_MASK_cntrl,
        /* 14 dc4 */ CTYPE_MASK_cntrl,
        /* 15 nak */ CTYPE_MASK_cntrl,
        /* 16 syn */ CTYPE_MASK_cntrl,
        /* 17 etb */ CTYPE_MASK_cntrl,
        /* 18 can */ CTYPE_MASK_cntrl,
        /* 19 em  */ CTYPE_MASK_cntrl,
        /* 1A sub */ CTYPE_MASK_cntrl,
        /* 1B esc */ CTYPE_MASK_cntrl,
        /* 1C fs  */ CTYPE_MASK_cntrl,
        /* 1D gs  */ CTYPE_MASK_cntrl,
        /* 1E rs  */ CTYPE_MASK_cntrl,
        /* 1F us  */ CTYPE_MASK_cntrl,
        /* 20     */ CTYPE_MASK_blank | CTYPE_MASK_print | CTYPE_MASK_space
                     | CTYPE_MASK_asn1print,
        /* 21  !  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 22  "  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 23  #  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 24  $  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 25  %  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 26  &  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 27  '  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct
                     | CTYPE_MASK_asn1print,
        /* 28  (  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct
                     | CTYPE_MASK_asn1print,
        /* 29  )  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct
                     | CTYPE_MASK_asn1print,
        /* 2A  *  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 2B  +  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 2C  ,  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct
                     | CTYPE_MASK_asn1print,
        /* 2D  -  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct
                     | CTYPE_MASK_asn1print,
        /* 2E  .  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct
                     | CTYPE_MASK_asn1print,
        /* 2F  /  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 30  0  */ CTYPE_MASK_digit | CTYPE_MASK_graph | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 31  1  */ CTYPE_MASK_digit | CTYPE_MASK_graph | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 32  2  */ CTYPE_MASK_digit | CTYPE_MASK_graph | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 33  3  */ CTYPE_MASK_digit | CTYPE_MASK_graph | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 34  4  */ CTYPE_MASK_digit | CTYPE_MASK_graph | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 35  5  */ CTYPE_MASK_digit | CTYPE_MASK_graph | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 36  6  */ CTYPE_MASK_digit | CTYPE_MASK_graph | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 37  7  */ CTYPE_MASK_digit | CTYPE_MASK_graph | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 38  8  */ CTYPE_MASK_digit | CTYPE_MASK_graph | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 39  9  */ CTYPE_MASK_digit | CTYPE_MASK_graph | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 3A  :  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct
                     | CTYPE_MASK_asn1print,
        /* 3B  ;  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 3C  <  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 3D  =  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 3E  >  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 3F  ?  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct
                     | CTYPE_MASK_asn1print,
        /* 40  @  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 41  A  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 42  B  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 43  C  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 44  D  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 45  E  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 46  F  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 47  G  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 48  H  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 49  I  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 4A  J  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 4B  K  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 4C  L  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 4D  M  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 4E  N  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 4F  O  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 50  P  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 51  Q  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 52  R  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 53  S  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 54  T  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 55  U  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 56  V  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 57  W  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 58  X  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 59  Y  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 5A  Z  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_upper
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 5B  [  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 5C  \  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 5D  ]  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 5E  ^  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 5F  _  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 60  `  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 61  a  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 62  b  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 63  c  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 64  d  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 65  e  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 66  f  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 67  g  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 68  h  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 69  i  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 6A  j  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 6B  k  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 6C  l  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 6D  m  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 6E  n  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 6F  o  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 70  p  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 71  q  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 72  r  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 73  s  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 74  t  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 75  u  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 76  v  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 77  w  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 78  x  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 79  y  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 7A  z  */ CTYPE_MASK_graph | CTYPE_MASK_lower | CTYPE_MASK_print
                     | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,
        /* 7B  {  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 7C  |  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 7D  }  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 7E  ~  */ CTYPE_MASK_graph | CTYPE_MASK_print | CTYPE_MASK_punct,
        /* 7F del */ CTYPE_MASK_cntrl
};

const unsigned char os_toascii[256] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

int ossl_toascii(int c)
{
    if (c < -128 || c > 256 || c == EOF)
        return c;
    /*
     * Adjust negatively signed characters.
     * This is not required for ASCII because any character that sign extends
     * is not seven bit and all of the checks are on the seven bit characters.
     * I.e. any check must fail on sign extension.
     */
    if (c < 0)
        c += 256;
    return os_toascii[c];
}



int ossl_ctype_check(int c, unsigned int mask)
{
    const int max = sizeof(ctype_char_map) / sizeof(*ctype_char_map);
    const int a = ossl_toascii(c);

    return a >= 0 && a < max && (ctype_char_map[a] & mask) != 0;
}

# define ossl_isbase64(c)       (ossl_ctype_check((c), CTYPE_MASK_base64))
# define ossl_iscntrl(c)        (ossl_ctype_check((c), CTYPE_MASK_cntrl))


/* Some helpers for PEM_read_bio_ex(). */
static int sanitize_line(char *linebuf, int len, unsigned int flags)
{
    int i;

    if (flags & PEM_FLAG_EAY_COMPATIBLE) {
        /* Strip trailing whitespace */
        while ((len >= 0) && (linebuf[len] <= ' '))
            len--;
        /* Go back to whitespace before applying uniform line ending. */
        len++;
    } else if (flags & PEM_FLAG_ONLY_B64) {
        for (i = 0; i < len; ++i) {
            if (!ossl_isbase64(linebuf[i]) || linebuf[i] == '\n'
                || linebuf[i] == '\r')
                break;
        }
        len = i;
    } else {
        /* EVP_DecodeBlock strips leading and trailing whitespace, so just strip
         * control characters in-place and let everything through. */
        for (i = 0; i < len; ++i) {
            if (linebuf[i] == '\n' || linebuf[i] == '\r')
                break;
            if (ossl_iscntrl(linebuf[i]))
                linebuf[i] = ' ';
        }
        len = i;
    }
    /* The caller allocated LINESIZE+1, so this is safe. */
    linebuf[len++] = '\n';
    linebuf[len] = '\0';
    return len;
}

#define LINESIZE 255
/* Note trailing spaces for begin and end. */
static const char beginstr[] = "-----BEGIN ";
static const char endstr[] = "-----END ";
static const char tailstr[] = "-----\n";
#define BEGINLEN ((int)(sizeof(beginstr) - 1))
#define ENDLEN ((int)(sizeof(endstr) - 1))
#define TAILLEN ((int)(sizeof(tailstr) - 1))
static int get_name(BIO *bp, char **name, unsigned int flags)
{
    char *linebuf;
    int ret = 0;
    int len;

    linebuf = (char *)pem_malloc(LINESIZE + 1, flags);
    if (linebuf == NULL) {
        eosio_assert(false, "PEM_F_GET_NAME, ERR_R_MALLOC_FAILURE");
        return 0;
    }

    do {
        len = BIO_gets(bp, linebuf, LINESIZE);
        if (len <= 0) {
            goto err;
        }

        /* Strip trailing garbage and standardize ending. */
        len = sanitize_line(linebuf, len, flags & ~PEM_FLAG_ONLY_B64);

        /* Allow leading empty or non-matching lines. */
    } while (strncmp(linebuf, beginstr, BEGINLEN) != 0
             || len < TAILLEN
             || strncmp(linebuf + len - TAILLEN, tailstr, TAILLEN) != 0);
    linebuf[len - TAILLEN] = '\0';
    len = len - BEGINLEN - TAILLEN + 1;
    *name = (char *)pem_malloc(len, flags);
    if (*name == NULL) {
        goto err;
    }
    memcpy(*name, linebuf + BEGINLEN, len);
    ret = 1;

    err:
    pem_free(linebuf, flags, LINESIZE + 1);
    return ret;
}


enum header_status {
    MAYBE_HEADER,
    IN_HEADER,
    POST_HEADER
};


int BIO_puts(BIO *b, const char *buf)
{
    int ret;
    size_t written = 0;

    if(b == NULL){
        eosio_assert(false, "b == NULL");
    }
    if(b->method == NULL){
        eosio_assert(false, "b->method == NULL");
    }
    if(b->method->bputs == NULL){
        eosio_assert(false, "b->method->bputs == NULL");
    }
    if(!b->init){
        eosio_assert(false, "!b->init");
    }
    ret = b->method->bputs(b, buf);

    if (ret > 0) {
        b->num_write += (uint64_t)ret;
        written = ret;
        ret = 1;
    }

    if (ret > 0) {
        if (written > INT_MAX) {
            eosio_assert(false, "BIO_F_BIO_PUTS, BIO_R_LENGTH_TOO_LONG");
            ret = -1;
        } else {
            ret = (int)written;
        }
    }

    return ret;
}


static int get_header_and_data(BIO *bp, BIO **header, BIO **data, char *name,
                               unsigned int flags)
{
    BIO *tmp = *header;
    char *linebuf, *p;
    int len, line, ret = 0, end = 0;
    /* 0 if not seen (yet), 1 if reading header, 2 if finished header */
    enum header_status got_header = MAYBE_HEADER;
    unsigned int flags_mask;
    size_t namelen;

    /* Need to hold trailing NUL (accounted for by BIO_gets() and the newline
     * that will be added by sanitize_line() (the extra '1'). */
    linebuf = (char *)pem_malloc(LINESIZE + 1, flags);
    if (linebuf == NULL) {
        eosio_assert(false, "PEM_F_GET_HEADER_AND_DATA, ERR_R_MALLOC_FAILURE");
        return 0;
    }

    for (line = 0; ; line++) {
        flags_mask = ~0u;
        len = BIO_gets(bp, linebuf, LINESIZE);
        if (len <= 0) {
            goto err;
        }

        if (got_header == MAYBE_HEADER) {
            if (memchr(linebuf, ':', len) != NULL)
                got_header = IN_HEADER;
        }
        if (!strncmp(linebuf, endstr, ENDLEN) || got_header == IN_HEADER)
            flags_mask &= ~PEM_FLAG_ONLY_B64;
        len = sanitize_line(linebuf, len, flags & flags_mask);

        /* Check for end of header. */
        if (linebuf[0] == '\n') {
            if (got_header == POST_HEADER) {
                /* Another blank line is an error. */
                goto err;
            }
            got_header = POST_HEADER;
            tmp = *data;
            continue;
        }

        /* Check for end of stream (which means there is no header). */
        if (strncmp(linebuf, endstr, ENDLEN) == 0) {
            p = linebuf + ENDLEN;
            namelen = strlen(name);
            if (strncmp(p, name, namelen) != 0 ||
                strncmp(p + namelen, tailstr, TAILLEN) != 0) {
                goto err;
            }
            if (got_header == MAYBE_HEADER) {
                *header = *data;
                *data = tmp;
            }
            break;
        } else if (end) {
            /* Malformed input; short line not at end of data. */
            goto err;
        }
        /*
         * Else, a line of text -- could be header or data; we don't
         * know yet.  Just pass it through.
         */
        if (BIO_puts(tmp, linebuf) < 0)
            goto err;
        /*
         * Only encrypted files need the line length check applied.
         */
        if (got_header == POST_HEADER) {
            /* 65 includes the trailing newline */
            if (len > 65)
                goto err;
            if (len < 65)
                end = 1;
        }
    }

    ret = 1;
    err:
    pem_free(linebuf, flags, LINESIZE + 1);
    return ret;
}

void EVP_DecodeInit(EVP_ENCODE_CTX *ctx)
{
    /* Only ctx->num and ctx->flags are used during decoding. */
    ctx->num = 0;
    ctx->length = 0;
    ctx->line_num = 0;
    ctx->flags = 0;
}

long BIO_ctrl(BIO *b, int cmd, long larg, void *parg)
{
    long ret;

    if (b == NULL)
        return 0;

    if ((b->method == NULL) || (b->method->ctrl == NULL)) {
        eosio_assert(false,"BIO_F_BIO_CTRL, BIO_R_UNSUPPORTED_METHOD");
        return -2;
    }

    ret = b->method->ctrl(b, cmd, larg, parg);
    return ret;
}

# define BIO_C_GET_BUF_MEM_PTR                   115
# define BIO_get_mem_ptr(b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0, \
                                          (char *)(pp))

#define EVP_ENCODE_CTX_USE_SRP_ALPHABET     2
static const unsigned char data_ascii2bin[128] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xE0, 0xF0, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xF2, 0xFF, 0x3F,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const unsigned char srpdata_ascii2bin[128] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xE0, 0xF0, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF2, 0x3E, 0x3F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
        0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
        0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
        0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

#define B64_EOLN                0xF0
#define B64_CR                  0xF1
#define B64_EOF                 0xF2
#define B64_WS                  0xE0
#define B64_ERROR               0xFF
#define B64_NOT_BASE64(a)       (((a)|0x13) == 0xF3)
#define B64_BASE64(a)           (!B64_NOT_BASE64(a))
static unsigned char conv_ascii2bin(unsigned char a, const unsigned char *table)
{
    if (a & 0x80)
        return B64_ERROR;
    return table[a];
}




static int evp_decodeblock_int(EVP_ENCODE_CTX *ctx, unsigned char *t,
                               const unsigned char *f, int n)
{
    int i, ret = 0, a, b, c, d;
    unsigned long l;
    const unsigned char *table;

    if (ctx != NULL && (ctx->flags & EVP_ENCODE_CTX_USE_SRP_ALPHABET) != 0)
        table = srpdata_ascii2bin;
    else
        table = data_ascii2bin;

    /* trim white space from the start of the line. */
    while ((conv_ascii2bin(*f, table) == B64_WS) && (n > 0)) {
        f++;
        n--;
    }

    /*
     * strip off stuff at the end of the line ascii2bin values B64_WS,
     * B64_EOLN, B64_EOLN and B64_EOF
     */
    while ((n > 3) && (B64_NOT_BASE64(conv_ascii2bin(f[n - 1], table))))
        n--;

    if (n % 4 != 0)
        return -1;

    for (i = 0; i < n; i += 4) {
        a = conv_ascii2bin(*(f++), table);
        b = conv_ascii2bin(*(f++), table);
        c = conv_ascii2bin(*(f++), table);
        d = conv_ascii2bin(*(f++), table);
        if ((a & 0x80) || (b & 0x80) || (c & 0x80) || (d & 0x80))
            return -1;
        l = ((((unsigned long)a) << 18L) |
             (((unsigned long)b) << 12L) |
             (((unsigned long)c) << 6L) | (((unsigned long)d)));
        *(t++) = (unsigned char)(l >> 16L) & 0xff;
        *(t++) = (unsigned char)(l >> 8L) & 0xff;
        *(t++) = (unsigned char)(l) & 0xff;
        ret += 3;
    }
    return ret;
}

int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)
{
    int i;

    *outl = 0;
    if (ctx->num != 0) {
        i = evp_decodeblock_int(ctx, out, ctx->enc_data, ctx->num);
        if (i < 0)
            return -1;
        ctx->num = 0;
        *outl = i;
        return 1;
    } else
        return 1;
}


int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl)
{
    int seof = 0, eof = 0, rv = -1, ret = 0, i, v, tmp, n, decoded_len;
    unsigned char *d;
    const unsigned char *table;

    n = ctx->num;
    d = ctx->enc_data;

    if (n > 0 && d[n - 1] == '=') {
        eof++;
        if (n > 1 && d[n - 2] == '=')
            eof++;
    }

    /* Legacy behaviour: an empty input chunk signals end of input. */
    if (inl == 0) {
        rv = 0;
        goto end;
    }

    if ((ctx->flags & EVP_ENCODE_CTX_USE_SRP_ALPHABET) != 0)
        table = srpdata_ascii2bin;
    else
        table = data_ascii2bin;

    for (i = 0; i < inl; i++) {
        tmp = *(in++);
        v = conv_ascii2bin(tmp, table);
        if (v == B64_ERROR) {
            rv = -1;
            goto end;
        }

        if (tmp == '=') {
            eof++;
        } else if (eof > 0 && B64_BASE64(v)) {
            /* More data after padding. */
            rv = -1;
            goto end;
        }

        if (eof > 2) {
            rv = -1;
            goto end;
        }

        if (v == B64_EOF) {
            seof = 1;
            goto tail;
        }

        /* Only save valid base64 characters. */
        if (B64_BASE64(v)) {
            if (n >= 64) {
                /*
                 * We increment n once per loop, and empty the buffer as soon as
                 * we reach 64 characters, so this can only happen if someone's
                 * manually messed with the ctx. Refuse to write any more data.
                 */
                rv = -1;
                goto end;
            }

            if(n >= (int)sizeof(ctx->enc_data)){
                eosio_assert(false, "n >= (int)sizeof(ctx->enc_data)");
            }
            d[n++] = tmp;
        }

        if (n == 64) {
            decoded_len = evp_decodeblock_int(ctx, out, d, n);
            n = 0;
            if (decoded_len < 0 || eof > decoded_len) {
                rv = -1;
                goto end;
            }
            ret += decoded_len - eof;
            out += decoded_len - eof;
        }
    }

    tail:
    if (n > 0) {
        if ((n & 3) == 0) {
            decoded_len = evp_decodeblock_int(ctx, out, d, n);
            n = 0;
            if (decoded_len < 0 || eof > decoded_len) {
                rv = -1;
                goto end;
            }
            ret += (decoded_len - eof);
        } else if (seof) {
            /* EOF in the middle of a base64 block. */
            rv = -1;
            goto end;
        }
    }

    rv = seof || (n == 0 && eof) ? 0 : 1;
    end:
    /* Legacy behaviour. This should probably rather be zeroed on error. */
    *outl = ret;
    ctx->num = n;
    return rv;
}

# define BIO_CTRL_INFO           3/* opt - extra tit-bits */
# define BIO_get_mem_data(b,pp)  BIO_ctrl(b,BIO_CTRL_INFO,0,(char *)(pp))

static int bio_read_intern(BIO *b, void *data, size_t dlen, size_t *readbytes)
{
    int ret;

    if(b == NULL){
        eosio_assert(false, "b == NULL");
    }
    if(b->method == NULL){
        eosio_assert(false, "b->method == NULL");
    }
    if(b->method->bread == NULL){
        eosio_assert(false, "b->method->bread == NULL");
    }
    if(!b->init){
        eosio_assert(false, "!b->init");
    }

    ret = b->method->bread(b, (char *)data, dlen, readbytes);

    if (ret > 0)
        b->num_read += (uint64_t)*readbytes;

    if (ret > 0 && *readbytes > dlen) {
        eosio_assert(false,"BIO_F_BIO_READ_INTERN, ERR_R_INTERNAL_ERROR");
        return -1;
    }

    return ret;
}


int BIO_read(BIO *b, void *data, int dlen)
{
    size_t readbytes;
    int ret;

    if (dlen < 0)
        return 0;

    ret = bio_read_intern(b, data, (size_t)dlen, &readbytes);

    if (ret > 0) {
        /* *readbytes should always be <= dlen */
        ret = (int)readbytes;
    }

    return ret;
}


int PEM_read_bio_ex(BIO *bp, char **name_out, char **header,
                    unsigned char **data, long *len_out, unsigned int flags)
{
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    const BIO_METHOD *bmeth;
    BIO *headerB = NULL, *dataB = NULL;
    char *name = NULL;
    int len, taillen, headerlen, ret = 0;
    BUF_MEM * buf_mem;

    if (ctx == NULL) {
        eosio_assert(false, "PEM_F_PEM_READ_BIO_EX, ERR_R_MALLOC_FAILURE");
        return 0;
    }

    *len_out = 0;
    *name_out = *header = NULL;
    *data = NULL;
    if ((flags & PEM_FLAG_EAY_COMPATIBLE) && (flags & PEM_FLAG_ONLY_B64)) {
        /* These two are mutually incompatible; bail out. */
        eosio_assert(false, "PEM_F_PEM_READ_BIO_EX, ERR_R_PASSED_INVALID_ARGUMENT");
        goto end;
    }
    bmeth = (flags & PEM_FLAG_SECURE) ? BIO_s_secmem() : BIO_s_mem();

    headerB = BIO_new(bmeth);
    dataB = BIO_new(bmeth);
    if (headerB == NULL || dataB == NULL) {
        goto end;
    }

    if (!get_name(bp, &name, flags))
        goto end;
    if (!get_header_and_data(bp, &headerB, &dataB, name, flags))
        goto end;

    EVP_DecodeInit(ctx);
    BIO_get_mem_ptr(dataB, &buf_mem);
    len = buf_mem->length;
    if (EVP_DecodeUpdate(ctx, (unsigned char*)buf_mem->data, &len,
                         (unsigned char*)buf_mem->data, len) < 0
        || EVP_DecodeFinal(ctx, (unsigned char*)&(buf_mem->data[len]),
                           &taillen) < 0) {
        goto end;
    }
    len += taillen;
    buf_mem->length = len;

    /* There was no data in the PEM file; avoid malloc(0). */
    if (len == 0)
        goto end;
    headerlen = BIO_get_mem_data(headerB, NULL);
    *header = (char *)pem_malloc(headerlen + 1, flags);
    *data = (unsigned char *)pem_malloc(len, flags);
    if (*header == NULL || *data == NULL) {
        pem_free(*header, flags, 0);
        pem_free(*data, flags, 0);
        goto end;
    }
    BIO_read(headerB, *header, headerlen);
    (*header)[headerlen] = '\0';
    BIO_read(dataB, *data, len);
    *len_out = len;
    *name_out = name;
    name = NULL;
    ret = 1;

    end:
    EVP_ENCODE_CTX_free(ctx);
    pem_free(name, flags, 0);
    BIO_free(headerB);
    BIO_free(dataB);
    return ret;
}


int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher)
{
    static const char ProcType[] = "Proc-Type:";
    static const char ENCRYPTED[] = "ENCRYPTED";
    static const char DEKInfo[] = "DEK-Info:";
    const EVP_CIPHER *enc = NULL;
    int ivlen;
    char *dekinfostart, c;

    cipher->cipher = NULL;
    memset(cipher->iv, 0, sizeof(cipher->iv));
    if ((header == NULL) || (*header == '\0') || (*header == '\n'))
        return 1;

    return 0;
}

int PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *plen)
{
    int ok;
    int keylen;
    long len = *plen;
    int ilen = (int) len;       /* EVP_DecryptUpdate etc. take int lengths */
    EVP_CIPHER_CTX *ctx;

#if LONG_MAX > INT_MAX
    /* Check that we did not truncate the length */
    if (len > INT_MAX) {
        eosio_assert(false, "PEM_F_PEM_DO_HEADER, PEM_R_HEADER_TOO_LONG");
        return 0;
    }
#endif

    if (cipher->cipher == NULL)
        return 1;

    return 0;
}


static int pem_bytes_read_bio_flags(unsigned char **pdata, long *plen,
                                    char **pnm, const char *name, BIO *bp,
                                    /*pem_password_cb *cb, void *u,*/
                                    unsigned int flags)
{
    EVP_CIPHER_INFO cipher;
    char *nm = NULL, *header = NULL;
    unsigned char *data = NULL;
    long len = 0;
    int ret = 0;


    pem_free(nm, flags, 0);
    pem_free(header, flags, 0);
    pem_free(data, flags, len);
    if (!PEM_read_bio_ex(bp, &nm, &header, &data, &len, flags)) {
        return 0;
    }

    if (!PEM_get_EVP_CIPHER_INFO(header, &cipher))
        goto err;
    if (!PEM_do_header(&cipher, data, &len))
        goto err;

    *pdata = data;
    *plen = len;

    if (pnm != NULL)
        *pnm = nm;

    ret = 1;

    err:
    if (!ret || pnm == NULL)
        pem_free(nm, flags, 0);
    pem_free(header, flags, 0);
    if (!ret)
        pem_free(data, flags, len);
    return ret;
}


int PEM_bytes_read_bio_secmem(unsigned char **pdata, long *plen, char **pnm,
                              const char *name, BIO *bp) {
    return pem_bytes_read_bio_flags(pdata, plen, pnm, name, bp,
                                    PEM_FLAG_SECURE | PEM_FLAG_EAY_COMPATIBLE);
}

#define NID_undef                       0
# define EVP_PKEY_NONE   NID_undef

EVP_PKEY *EVP_PKEY_new(void)
{
    EVP_PKEY *ret = (EVP_PKEY *)CRYPTO_zalloc(sizeof(*ret));

    if (ret == NULL) {
        eosio_assert(false,"EVP_F_EVP_PKEY_NEW, ERR_R_MALLOC_FAILURE");
        return NULL;
    }

    ret->type = EVP_PKEY_NONE;
    ret->save_type = EVP_PKEY_NONE;
    ret->references = 1;
    ret->save_parameters = 1;
    return ret;
}

typedef struct ASN1_ITEM_st ASN1_ITEM;
typedef const ASN1_ITEM ASN1_ITEM_EXP;

struct ASN1_TEMPLATE_st {
    unsigned long flags;        /* Various flags */
    long tag;                   /* tag, not used if no tagging */
    unsigned long offset;       /* Offset of this field in structure */
    const char *field_name;     /* Field name */
    ASN1_ITEM_EXP *item;        /* Relevant ASN1_ITEM or ASN1_ADB */
};
typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;

struct ASN1_ITEM_st {
    char itype;                 /* The item type, primitive, SEQUENCE, CHOICE
                                 * or extern */
    long utype;                 /* underlying type */
    const ASN1_TEMPLATE *templates; /* If SEQUENCE or CHOICE this contains
                                     * the contents */
    long tcount;                /* Number of templates if SEQUENCE or CHOICE */
    const void *funcs;          /* functions that handle this type */
    long size;                  /* Structure size (usually) */
    const char *sname;          /* Structure name */
};

struct ASN1_TLC_st {
    char valid;                 /* Values below are valid */
    int ret;                    /* return value */
    long plen;                  /* length */
    int ptag;                   /* class value */
    int pclass;                 /* class value */
    int hdrlen;                 /* header length */
};

typedef struct ASN1_TLC_st ASN1_TLC;
struct asn1_pctx_st {
    unsigned long flags;
    unsigned long nm_flags;
    unsigned long cert_flags;
    unsigned long oid_flags;
    unsigned long str_flags;
} /* ASN1_PCTX */ ;

typedef int ASN1_aux_cb(int operation, ASN1_VALUE **in, const ASN1_ITEM *it,
                        void *exarg);

typedef struct ASN1_AUX_st {
    void *app_data;
    int flags;
    int ref_offset;             /* Offset of reference value */
    int ref_lock;               /* Lock type to use */
    ASN1_aux_cb *asn1_cb;
    int enc_offset;             /* Offset of ASN1_ENCODING structure */
} ASN1_AUX;
#define asn1_tlc_clear_nc(c)    (c)->valid = 0
typedef struct asn1_pctx_st ASN1_PCTX;
typedef int ASN1_ex_new_func(ASN1_VALUE **pval, const ASN1_ITEM *it);
typedef void ASN1_ex_free_func(ASN1_VALUE **pval, const ASN1_ITEM *it);
typedef int ASN1_ex_print_func(BIO *out, ASN1_VALUE **pval,
                               int indent, const char *fname,
                               const ASN1_PCTX *pctx);

typedef int ASN1_ex_d2i(ASN1_VALUE **pval, const unsigned char **in, long len,
                        const ASN1_ITEM *it, int tag, int aclass, char opt,
                        ASN1_TLC *ctx);

typedef int ASN1_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
                        const ASN1_ITEM *it, int tag, int aclass);

typedef struct ASN1_EXTERN_FUNCS_st {
    void *app_data;
    ASN1_ex_new_func *asn1_ex_new;
    ASN1_ex_free_func *asn1_ex_free;
    ASN1_ex_free_func *asn1_ex_clear;
    ASN1_ex_d2i *asn1_ex_d2i;
    ASN1_ex_i2d *asn1_ex_i2d;
    ASN1_ex_print_func *asn1_ex_print;
} ASN1_EXTERN_FUNCS;

#define ASN1_MAX_CONSTRUCTED_NEST 30
# define ASN1_ITYPE_NDEF_SEQUENCE        0x6
# define ASN1_ITYPE_SEQUENCE             0x1
# define V_ASN1_SEQUENCE                 16
# define V_ASN1_UNIVERSAL                0x00
# define ASN1_AFLG_BROKEN        4
# define ASN1_OP_D2I_PRE         4
# define ASN1_TFLG_ADB_MASK      (0x3<<8)
# define ASN1_TFLG_OPTIONAL      (0x1)
# define V_ASN1_PRIMITIVE_TAG            0x1f
# define V_ASN1_CONSTRUCTED              0x20
# define V_ASN1_PRIVATE                  0xc0


static int asn1_get_length(const unsigned char **pp, int *inf, long *rl,
                           long max)
{
    const unsigned char *p = *pp;
    unsigned long ret = 0;
    int i;

    if (max-- < 1)
        return 0;
    if (*p == 0x80) {
        *inf = 1;
        p++;
    } else {
        *inf = 0;
        i = *p & 0x7f;
        if (*p++ & 0x80) {
            if (max < i + 1)
                return 0;
            /* Skip leading zeroes */
            while (i > 0 && *p == 0) {
                p++;
                i--;
            }
            if (i > (int)sizeof(long))
                return 0;
            while (i > 0) {
                ret <<= 8;
                ret |= *p++;
                i--;
            }
            if (ret > LONG_MAX)
                return 0;
        } else
            ret = i;
    }
    *pp = p;
    *rl = (long)ret;
    return 1;
}

int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
                    int *pclass, long omax)
{
    int i, ret;
    long l;
    const unsigned char *p = *pp;
    int tag, xclass, inf;
    long max = omax;

    if (!max)
        goto err;
    ret = (*p & V_ASN1_CONSTRUCTED);
    xclass = (*p & V_ASN1_PRIVATE);
    i = *p & V_ASN1_PRIMITIVE_TAG;
    if (i == V_ASN1_PRIMITIVE_TAG) { /* high-tag */
        p++;
        if (--max == 0)
            goto err;
        l = 0;
        while (*p & 0x80) {
            l <<= 7L;
            l |= *(p++) & 0x7f;
            if (--max == 0)
                goto err;
            if (l > (INT_MAX >> 7L))
                goto err;
        }
        l <<= 7L;
        l |= *(p++) & 0x7f;
        tag = (int)l;
        if (--max == 0)
            goto err;
    } else {
        tag = i;
        p++;
        if (--max == 0)
            goto err;
    }
    *ptag = tag;
    *pclass = xclass;
    if (!asn1_get_length(&p, &inf, plength, max))
        goto err;

    if (inf && !(ret & V_ASN1_CONSTRUCTED))
        goto err;

    if (*plength > (omax - (p - *pp))) {
        /*
         * Set this so that even if things are not long enough the values are
         * set correctly
         */
        ret |= 0x80;
    }
    *pp = p;
    return ret | inf;
    err:
    return 0x80;
}

#define asn1_tlc_clear(c)       if (c) (c)->valid = 0
static int asn1_check_tlen(long *olen, int *otag, unsigned char *oclass,
                           char *inf, char *cst,
                           const unsigned char **in, long len,
                           int exptag, int expclass, char opt, ASN1_TLC *ctx)
{
    int i;
    int ptag, pclass;
    long plen;
    const unsigned char *p, *q;
    p = *in;
    q = p;

    if (ctx && ctx->valid) {
        i = ctx->ret;
        plen = ctx->plen;
        pclass = ctx->pclass;
        ptag = ctx->ptag;
        p += ctx->hdrlen;
    } else {
        i = ASN1_get_object(&p, &plen, &ptag, &pclass, len);
        if (ctx) {
            ctx->ret = i;
            ctx->plen = plen;
            ctx->pclass = pclass;
            ctx->ptag = ptag;
            ctx->hdrlen = p - q;
            ctx->valid = 1;
            /*
             * If definite length, and no error, length + header can't exceed
             * total amount of data available.
             */
            if (!(i & 0x81) && ((plen + ctx->hdrlen) > len)) {
                asn1_tlc_clear(ctx);
                eosio_assert(false, "!(i & 0x81) && ((plen + ctx->hdrlen) > len)");
            }
        }
    }

    if (i & 0x80) {
        asn1_tlc_clear(ctx);
        return 0;
    }
    if (exptag >= 0) {
        if ((exptag != ptag) || (expclass != pclass)) {
            if (opt)
                eosio_assert(false, "asn1_check_tlen opt");
            asn1_tlc_clear(ctx);
            eosio_assert(false, "(exptag != ptag) || (expclass != pclass)");
        }
        asn1_tlc_clear(ctx);
    }

    if (i & 1)
        plen = len - (p - q);

    if (inf)
        *inf = i & 1;

    if (cst)
        *cst = i & V_ASN1_CONSTRUCTED;

    if (olen)
        *olen = plen;

    if (oclass)
        *oclass = pclass;

    if (otag)
        *otag = ptag;

    *in = p;
    return 1;
}

# define ASN1_OP_NEW_PRE         0
# define ASN1_AFLG_ENCODING      2
#define offset2ptr(addr, offset) (void *)(((char *) addr) + offset)
typedef struct ASN1_ENCODING_st {
    unsigned char *enc;         /* DER encoding */
    long len;                   /* Length of encoding */
    int modified;               /* set to 1 if 'enc' is invalid */
} ASN1_ENCODING;

static ASN1_ENCODING *asn1_get_enc_ptr(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    const ASN1_AUX *aux;
    if (!pval || !*pval)
        return NULL;
    aux = (const ASN1_AUX *)it->funcs;
    if (!aux || !(aux->flags & ASN1_AFLG_ENCODING))
        return NULL;
    return (ASN1_ENCODING_st *)offset2ptr(*pval, aux->enc_offset);
}


void asn1_enc_init(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    ASN1_ENCODING *enc;
    enc = asn1_get_enc_ptr(pval, it);
    if (enc) {
        enc->enc = NULL;
        enc->len = 0;
        enc->modified = 1;
    }
}


ASN1_VALUE **asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
    ASN1_VALUE **pvaltmp;
    pvaltmp = (ASN1_VALUE **)offset2ptr(*pval, tt->offset);
    /*
     * NOTE for BOOLEAN types the field is just a plain int so we can't
     * return int **, so settle for (int *).
     */
    return pvaltmp;
}

#  define ASN1_ITEM_ptr(iptr) (iptr)
# define ASN1_TFLG_EMBED         (0x1 << 12)
# define ASN1_TFLG_SK_MASK       (0x3 << 1)
static void asn1_item_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    switch (it->itype) {
        case ASN1_ITYPE_SEQUENCE:
        case ASN1_ITYPE_NDEF_SEQUENCE:
            *pval = NULL;
            break;
    }
}
static void asn1_template_clear(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
    /* If ADB or STACK just NULL the field */
    if (tt->flags & (ASN1_TFLG_ADB_MASK | ASN1_TFLG_SK_MASK))
        *pval = NULL;
    else
        asn1_item_clear(pval, ASN1_ITEM_ptr(tt->item));
}

static int asn1_template_new(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);
# define ASN1_ITYPE_PRIMITIVE            0x0
# define ASN1_OP_FREE_PRE        2

void asn1_enc_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    ASN1_ENCODING *enc;
    enc = asn1_get_enc_ptr(pval, it);
    if (enc) {
        CRYPTO_free(enc->enc);
        enc->enc = NULL;
        enc->len = 0;
        enc->modified = 1;
    }
}

# define ASN1_OP_NEW_POST        1
void asn1_item_embed_free(ASN1_VALUE **pval, const ASN1_ITEM *it, int embed)
{
    const ASN1_TEMPLATE *tt = NULL, *seqtt;
    const ASN1_EXTERN_FUNCS *ef;
    const ASN1_AUX *aux = (const ASN1_AUX *)it->funcs;
    ASN1_aux_cb *asn1_cb;
    int i;

    if (pval != NULL)
        return;
    if ((it->itype != ASN1_ITYPE_PRIMITIVE) && !*pval)
        return;
    if (aux != NULL && aux->asn1_cb != NULL)
        asn1_cb = aux->asn1_cb;
    else
        asn1_cb = 0;

    switch (it->itype) {
        case ASN1_ITYPE_NDEF_SEQUENCE:
        case ASN1_ITYPE_SEQUENCE:
            if (asn1_cb) {
                i = asn1_cb(ASN1_OP_FREE_PRE, pval, it, NULL);
                if (i == 2)
                    return;
            }
            asn1_enc_free(pval, it);
            /*
             * If we free up as normal we will invalidate any ANY DEFINED BY
             * field and we won't be able to determine the type of the field it
             * defines. So free up in reverse order.
             */
            tt = it->templates + it->tcount;
            for (i = 0; i < it->tcount; i++) {
                ASN1_VALUE **pseqval;

                tt--;
//                seqtt = asn1_do_adb(pval, tt, 0);
                if (!seqtt)
                    continue;
                pseqval = asn1_get_field_ptr(pval, seqtt);
               // asn1_template_free(pseqval, seqtt);
            }
//            if (asn1_cb)
//                asn1_cb(ASN1_OP_FREE_POST, pval, it, NULL);
//            if (embed == 0) {
//                CRYPTO_free(*pval);
//                *pval = NULL;
//            }
            break;
    }
}

int asn1_item_embed_new(ASN1_VALUE **pval, const ASN1_ITEM *it, int embed)
{
    const ASN1_TEMPLATE *tt = NULL;
    const ASN1_EXTERN_FUNCS *ef;
    const ASN1_AUX *aux = (const ASN1_AUX_st *)it->funcs;
    ASN1_aux_cb *asn1_cb;
    ASN1_VALUE **pseqval;
    int i;
    if (aux != NULL && aux->asn1_cb != NULL)
        asn1_cb = aux->asn1_cb;
    else
        asn1_cb = 0;

    switch (it->itype) {
        case ASN1_ITYPE_NDEF_SEQUENCE:
        case ASN1_ITYPE_SEQUENCE:
            if (asn1_cb) {
                i = asn1_cb(ASN1_OP_NEW_PRE, pval, it, NULL);
                if (!i)
                    goto auxerr;
                if (i == 2) {
                    return 1;
                }
            }
            if (embed) {
                memset(*pval, 0, it->size);
            } else {
                *pval = (ASN1_VALUE *)CRYPTO_zalloc(it->size);
                if (*pval == NULL)
                    goto memerr;
            }
            asn1_enc_init(pval, it);
            for (i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
                pseqval = asn1_get_field_ptr(pval, tt);
                if (!asn1_template_new(pseqval, tt))
                    goto memerr2;
            }
            if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it, NULL))
                goto auxerr2;
            break;
    }

    return 1;

    memerr2:
    asn1_item_embed_free(pval, it, embed);
    memerr:
    return 0;

    auxerr2:
    asn1_item_embed_free(pval, it, embed);
    auxerr:
    return 0;

}

static int asn1_template_new(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
    const ASN1_ITEM *it = ASN1_ITEM_ptr(tt->item);
    int embed = tt->flags & ASN1_TFLG_EMBED;
    ASN1_VALUE *tval;
    int ret;
    if (embed) {
        tval = (ASN1_VALUE *)pval;
        pval = &tval;
    }
    if (tt->flags & ASN1_TFLG_OPTIONAL) {
        asn1_template_clear(pval, tt);
        return 1;
    }
    /* If ANY DEFINED BY nothing to do */

    if (tt->flags & ASN1_TFLG_ADB_MASK) {
        *pval = NULL;
        return 1;
    }

    /* Otherwise pass it back to the item routine */
    ret = asn1_item_embed_new(pval, it, embed);
    done:
    return ret;
}


int ASN1_item_ex_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    return asn1_item_embed_new(pval, it, 0);
}

static int asn1_check_eoc(const unsigned char **in, long len)
{
    const unsigned char *p;
    if (len < 2)
        return 0;
    p = *in;
    if (!p[0] && !p[1]) {
        *in += 2;
        return 1;
    }
    return 0;
}


# define ASN1_TFLG_TAG_CLASS     (0x3<<6)
# define ASN1_TFLG_EXPTAG        (0x2 << 3)

# define ASN1_TFLG_SET_OF        (0x1 << 1)
# define V_ASN1_SET                      17
# define ASN1_TFLG_IMPTAG        (0x1 << 3)

static int asn1_item_embed_d2i(ASN1_VALUE **pval, const unsigned char **in,
                               long len, const ASN1_ITEM *it,
                               int tag, int aclass, char opt, ASN1_TLC *ctx,
                               int depth);

static int asn1_template_noexp_d2i(ASN1_VALUE **val,
                                   const unsigned char **in, long len,
                                   const ASN1_TEMPLATE *tt, char opt,
                                   ASN1_TLC *ctx, int depth)
{
    int flags, aclass;
    int ret;
    ASN1_VALUE *tval;
    const unsigned char *p, *q;
    if (!val)
        eosio_assert(false, "!val");
    flags = tt->flags;
    aclass = flags & ASN1_TFLG_TAG_CLASS;

    p = *in;
    q = p;

    if (tt->flags & ASN1_TFLG_EMBED) {
        tval = (ASN1_VALUE *)val;
        val = &tval;
    }

    ret = asn1_item_embed_d2i(val, &p, len, ASN1_ITEM_ptr(tt->item),
                              -1, 0, opt, ctx, depth);
    if (!ret) {
        eosio_assert(false, "asn1_template_noexp_d2i !ret");
    } else if (ret == -1)
        eosio_assert(false, "ret == -1");


    *in = p;
    return 1;
}


static int asn1_template_ex_d2i(ASN1_VALUE **val,
                                const unsigned char **in, long inlen,
                                const ASN1_TEMPLATE *tt, char opt,
                                ASN1_TLC *ctx, int depth)
{
    int flags, aclass;
    int ret;
    long len;
    const unsigned char *p, *q;
    char exp_eoc;
    if (!val)
        return 0;
    flags = tt->flags;
    aclass = flags & ASN1_TFLG_TAG_CLASS;

    p = *in;

    return asn1_template_noexp_d2i(val, in, inlen, tt, opt, ctx, depth);
}


const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt,
                                 int nullerr)
{
    if (!(tt->flags & ASN1_TFLG_ADB_MASK))
        return tt;

    return NULL;
}



int asn1_enc_save(ASN1_VALUE **pval, const unsigned char *in, int inlen,
                  const ASN1_ITEM *it)
{
    ASN1_ENCODING *enc;
    enc = asn1_get_enc_ptr(pval, it);
    if (!enc)
        return 1;

    CRYPTO_free(enc->enc);
    if ((enc->enc = (unsigned char *)CRYPTO_malloc(inlen)) == NULL) {
        eosio_assert(false, "ASN1_F_ASN1_ENC_SAVE, ERR_R_MALLOC_FAILURE");
        return 0;
    }
    memcpy(enc->enc, in, inlen);
    enc->len = inlen;
    enc->modified = 0;

    return 1;
}

typedef int (*OPENSSL_sk_compfunc)(const void *, const void *);
struct stack_st {
    int num;
    const void **data;
    int sorted;
    int num_alloc;
    OPENSSL_sk_compfunc comp;
};
typedef struct stack_st OPENSSL_STACK; /* Use STACK_OF(...) instead */

void OPENSSL_sk_free(OPENSSL_STACK *st)
{
    if (st == NULL)
        return;
    CRYPTO_free(st->data);
    CRYPTO_free(st);
}

int OPENSSL_sk_num(const OPENSSL_STACK *st)
{
    return st == NULL ? -1 : st->num;
}

void *OPENSSL_sk_value(const OPENSSL_STACK *st, int i)
{
    if (st == NULL || i < 0 || i >= st->num)
        return NULL;
    return (void *)st->data[i];
}

#   define ossl_inline inline
# define SKM_DEFINE_STACK_OF(t1, t2, t3) \
    STACK_OF(t1); \
    typedef int (*sk_##t1##_compfunc)(const t3 * const *a, const t3 *const *b); \
    typedef void (*sk_##t1##_freefunc)(t3 *a); \
    typedef t3 * (*sk_##t1##_copyfunc)(const t3 *a); \
    static ossl_inline void sk_##t1##_free(STACK_OF(t1) *sk) \
    { \
        OPENSSL_sk_free((OPENSSL_STACK *)sk); \
    } \
    static ossl_inline t2 *sk_##t1##_value(const STACK_OF(t1) *sk, int idx) \
    { \
        return (t2 *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); \
    }\
    static ossl_inline int sk_##t1##_num(const STACK_OF(t1) *sk) \
    { \
        return OPENSSL_sk_num((const OPENSSL_STACK *)sk); \
    }

# define DEFINE_STACK_OF(t) SKM_DEFINE_STACK_OF(t, t, t)
DEFINE_STACK_OF(ASN1_VALUE)

void asn1_template_free(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
    int embed = tt->flags & ASN1_TFLG_EMBED;
    ASN1_VALUE *tval;
    if (embed) {
        tval = (ASN1_VALUE *)pval;
        pval = &tval;
    }
    if (tt->flags & ASN1_TFLG_SK_MASK) {
        STACK_OF(ASN1_VALUE) *sk = (STACK_OF(ASN1_VALUE) *)*pval;
        int i;

        for (i = 0; i < sk_ASN1_VALUE_num(sk); i++) {
            ASN1_VALUE *vtmp = sk_ASN1_VALUE_value(sk, i);

            asn1_item_embed_free(&vtmp, ASN1_ITEM_ptr(tt->item), embed);
        }
        sk_ASN1_VALUE_free(sk);
        *pval = NULL;
    } else {
        asn1_item_embed_free(pval, ASN1_ITEM_ptr(tt->item), embed);
    }
}

# define ASN1_ITYPE_MSTRING              0x5
# define V_ASN1_UNIVERSAL                0x00
# define V_ASN1_APPLICATION              0x40
# define V_ASN1_CONTEXT_SPECIFIC         0x80
# define V_ASN1_PRIVATE                  0xc0

# define V_ASN1_CONSTRUCTED              0x20
# define V_ASN1_PRIMITIVE_TAG            0x1f
# define V_ASN1_PRIMATIVE_TAG /*compat*/ V_ASN1_PRIMITIVE_TAG

# define V_ASN1_APP_CHOOSE               -2/* let the recipient choose */
# define V_ASN1_OTHER                    -3/* used in ASN1_TYPE */
# define V_ASN1_ANY                      -4/* used in ASN1 template code */

# define V_ASN1_UNDEF                    -1
/* ASN.1 tag values */
# define V_ASN1_EOC                      0
# define V_ASN1_BOOLEAN                  1 /**/
# define V_ASN1_INTEGER                  2
# define V_ASN1_BIT_STRING               3
# define V_ASN1_OCTET_STRING             4
# define V_ASN1_NULL                     5
# define V_ASN1_OBJECT                   6
# define V_ASN1_OBJECT_DESCRIPTOR        7
# define V_ASN1_EXTERNAL                 8
# define V_ASN1_REAL                     9
# define V_ASN1_ENUMERATED               10
# define V_ASN1_UTF8STRING               12
# define V_ASN1_SEQUENCE                 16
# define V_ASN1_SET                      17
# define V_ASN1_NUMERICSTRING            18 /**/
# define V_ASN1_PRINTABLESTRING          19
# define V_ASN1_T61STRING                20
# define V_ASN1_TELETEXSTRING            20/* alias */
# define V_ASN1_VIDEOTEXSTRING           21 /**/
# define V_ASN1_IA5STRING                22
# define V_ASN1_UTCTIME                  23
# define V_ASN1_GENERALIZEDTIME          24 /**/
# define V_ASN1_GRAPHICSTRING            25 /**/
# define V_ASN1_ISO64STRING              26 /**/
# define V_ASN1_VISIBLESTRING            26/* alias */
# define V_ASN1_GENERALSTRING            27 /**/
# define V_ASN1_UNIVERSALSTRING          28 /**/
# define V_ASN1_BMPSTRING                30
# define ASN1_MAX_STRING_NEST 5

typedef int ASN1_primitive_i2c(ASN1_VALUE **pval, unsigned char *cont,
                               int *putype, const ASN1_ITEM *it);
typedef int ASN1_primitive_c2i(ASN1_VALUE **pval, const unsigned char *cont,
                               int len, int utype, char *free_cont,
                               const ASN1_ITEM *it);



typedef struct ASN1_PRIMITIVE_FUNCS_st {
    void *app_data;
    unsigned long flags;
    ASN1_ex_new_func *prim_new;
    ASN1_ex_free_func *prim_free;
    ASN1_ex_free_func *prim_clear;
    ASN1_primitive_c2i *prim_c2i;
    ASN1_primitive_i2c *prim_i2c;
} ASN1_PRIMITIVE_FUNCS;


# define ASN1_OBJECT_FLAG_DYNAMIC         0x01/* internal use */
# define ASN1_OBJECT_FLAG_CRITICAL        0x02/* critical x509v3 object id */
# define ASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04/* internal use */
# define ASN1_OBJECT_FLAG_DYNAMIC_DATA    0x08/* internal use */

void ASN1_OBJECT_free(ASN1_OBJECT *a)
{
    if (a == NULL)
        return;
    if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_STRINGS) {
#ifndef CONST_STRICT            /* disable purely for compile-time strict
                                 * const checking. Doing this on a "real"
                                 * compile will cause memory leaks */
        CRYPTO_free((void*)a->sn);
        CRYPTO_free((void*)a->ln);
#endif
        a->sn = a->ln = NULL;
    }
    if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_DATA) {
        CRYPTO_free((void*)a->data);
        a->data = NULL;
        a->length = 0;
    }
    if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC)
        CRYPTO_free(a);
}

# define ASN1_STRING_FLAG_NDEF 0x010
void asn1_string_embed_free(ASN1_STRING *a, int embed)
{
    if (a == NULL)
        return;
    if (!(a->flags & ASN1_STRING_FLAG_NDEF))
        CRYPTO_free(a->data);
    if (embed == 0)
        CRYPTO_free(a);
}

void asn1_primitive_free(ASN1_VALUE **pval, const ASN1_ITEM *it, int embed)
{
    int utype;

    /* Special case: if 'it' is a primitive with a free_func, use that. */
    if (it) {
        const ASN1_PRIMITIVE_FUNCS *pf = (const ASN1_PRIMITIVE_FUNCS_st *)it->funcs;

        if (embed) {
            if (pf && pf->prim_clear) {
                pf->prim_clear(pval, it);
                return;
            }
        } else if (pf && pf->prim_free) {
            pf->prim_free(pval, it);
            return;
        }
    }

    /* Special case: if 'it' is NULL, free contents of ASN1_TYPE */
    if (!it) {
        ASN1_TYPE *typ = (ASN1_TYPE *)*pval;

        utype = typ->type;
        pval = &typ->value.asn1_value;
        if (!*pval)
            return;
    } else if (it->itype == ASN1_ITYPE_MSTRING) {
        utype = -1;
        if (!*pval)
            return;
    } else {
        utype = it->utype;
        if ((utype != V_ASN1_BOOLEAN) && !*pval)
            return;
    }

    switch (utype) {
        case V_ASN1_OBJECT:
            ASN1_OBJECT_free((ASN1_OBJECT *)*pval);
            break;

        case V_ASN1_BOOLEAN:
            if (it)
                *(ASN1_BOOLEAN *)pval = it->size;
            else
                *(ASN1_BOOLEAN *)pval = -1;
            return;

        case V_ASN1_NULL:
            break;

        case V_ASN1_ANY:
            asn1_primitive_free(pval, NULL, 0);
            CRYPTO_free(*pval);
            break;

        default:
            asn1_string_embed_free((ASN1_STRING *)*pval, embed);
            break;
    }
    *pval = NULL;
}


void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value)
{
    if (a->value.ptr != NULL) {
        ASN1_TYPE **tmp_a = &a;
        asn1_primitive_free((ASN1_VALUE **)tmp_a, NULL, 0);
    }
    a->type = type;
    if (type == V_ASN1_BOOLEAN)
        a->value.boolean = value ? 0xff : 0;
    else
        a->value.ptr = (char *)value;
}

static int asn1_ex_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
                       int utype, char *free_cont, const ASN1_ITEM *it)
{
    ASN1_VALUE **opval = NULL;
    ASN1_STRING *stmp;
    ASN1_TYPE *typ = NULL;
    int ret = 0;
    const ASN1_PRIMITIVE_FUNCS *pf;
    ASN1_INTEGER **tint;
    pf = (const ASN1_PRIMITIVE_FUNCS_st *)it->funcs;

    if (pf && pf->prim_c2i)
        return pf->prim_c2i(pval, cont, len, utype, free_cont, it);

    return ret;
}

static int collect_data(BUF_MEM *buf, const unsigned char **p, long plen)
{
    int len;
    if (buf) {
        len = buf->length;
        if (!BUF_MEM_grow_clean(buf, len + plen)) {
            eosio_assert(false, "BUF_MEM_grow_clean collect_data");
        }
        memcpy(buf->data + len, *p, plen);
    }
    *p += plen;
    return 1;
}

static int asn1_collect(BUF_MEM *buf, const unsigned char **in, long len,
                        char inf, int tag, int aclass, int depth)
{
    const unsigned char *p, *q;
    long plen;
    char cst, ininf;
    p = *in;
    inf &= 1;
    if (!buf && !inf) {
        *in += len;
        return 1;
    }
    while (len > 0) {
        q = p;
        /* Check for EOC */
        if (asn1_check_eoc(&p, len)) {
            /*
             * EOC is illegal outside indefinite length constructed form
             */
            if (!inf) {
                eosio_assert(false, "inf first");
            }
            inf = 0;
            break;
        }

        if (!asn1_check_tlen(&plen, NULL, NULL, &ininf, &cst, &p,
                             len, tag, aclass, 0, NULL)) {
            eosio_assert(false, "!asn1_check_tlen");
        }

        /* If indefinite length constructed update max length */
        if (cst) {
            if (depth >= ASN1_MAX_STRING_NEST) {
                eosio_assert(false, "depth >= ASN1_MAX_STRING_NEST");
            }
            if (!asn1_collect(buf, &p, plen, ininf, tag, aclass, depth + 1))
                return 0;
        } else if (plen && !collect_data(buf, &p, plen))
            return 0;
        len -= p - q;
    }
    if (inf) {
        eosio_assert(false, "inf");
    }
    *in = p;
    return 1;
}


static int asn1_find_end(const unsigned char **in, long len, char inf)
{
    uint32_t expected_eoc;
    long plen;
    const unsigned char *p = *in, *q;
    if (inf == 0) {
        *in += len;
        return 1;
    }
    expected_eoc = 1;
    while (len > 0) {
        if (asn1_check_eoc(&p, len)) {
            expected_eoc--;
            if (expected_eoc == 0)
                break;
            len -= 2;
            continue;
        }
        q = p;
        /* Just read in a header: only care about the length */
        if (!asn1_check_tlen(&plen, NULL, NULL, &inf, NULL, &p, len,
                             -1, 0, 0, NULL)) {
            eosio_assert(false, "eERR_R_NESTED_ASN1_ERROR");
        }
        if (inf) {
            if (expected_eoc == UINT32_MAX) {
                eosio_assert(false, "expected_eoc == UINT32_MAX");
            }
            expected_eoc++;
        } else {
            p += plen;
        }
        len -= p - q;
    }
    if (expected_eoc) {
        eosio_assert(false, "expected_eoc");
    }
    *in = p;
    return 1;
}


static int asn1_d2i_ex_primitive(ASN1_VALUE **pval,
                                 const unsigned char **in, long inlen,
                                 const ASN1_ITEM *it,
                                 int tag, int aclass, char opt, ASN1_TLC *ctx)
{
    int ret = 0, utype;
    long plen;
    char cst, inf, free_cont = 0;
    const unsigned char *p;
    BUF_MEM buf = { 0, NULL, 0, 0 };
    const unsigned char *cont = NULL;
    long len;
    if (pval == NULL) {
            eosio_assert(false, (char *)"pval is null");
    }

    if (it->itype == ASN1_ITYPE_MSTRING) {
        utype = tag;
        tag = -1;
    } else
        utype = it->utype;

    if (utype == V_ASN1_ANY) {
        /* If type is ANY need to figure out type from tag */
        unsigned char oclass;
        if(tag >= 0){
            eosio_assert(false, "tag >= 0");
        }
        if (opt) {
            eosio_assert(false, "opt");
        }
        p = *in;
        ret = asn1_check_tlen(NULL, &utype, &oclass, NULL, NULL,
                              &p, inlen, -1, 0, 0, ctx);
        if (!ret) {
            eosio_assert(false, "asn1_d2i_ex_primitive !ret first");
        }
        if (oclass != V_ASN1_UNIVERSAL)
            utype = V_ASN1_OTHER;
    }
    if (tag == -1) {
        tag = utype;
        aclass = V_ASN1_UNIVERSAL;
    }
    p = *in;
    ret = asn1_check_tlen(&plen, NULL, NULL, &inf, &cst,
                          &p, inlen, tag, aclass, opt, ctx);
    if (!ret) {
        eosio_assert(false, "asn1_d2i_ex_primitive !ret second");
    } else if (ret == -1)
        eosio_assert(false, "ret == -1");

    ret = 0;
    if ((utype == V_ASN1_SEQUENCE)
        || (utype == V_ASN1_SET) || (utype == V_ASN1_OTHER)) {
        if (utype == V_ASN1_OTHER) {
            asn1_tlc_clear(ctx);
        }
            /* SEQUENCE and SET must be constructed */
        else if (!cst) {
            eosio_assert(false, "!cst");
        }

        cont = *in;
        if (inf) {
            if (!asn1_find_end(&p, plen, inf)){
                if (free_cont)
                    CRYPTO_free(buf.data);
                eosio_assert(false, "!asn1_find_end(&p, plen, inf)");
            }

            len = p - cont;
        } else {
            len = p - cont + plen;
            p += plen;
        }
    } else if (cst) {
        if (utype == V_ASN1_NULL || utype == V_ASN1_BOOLEAN
            || utype == V_ASN1_OBJECT || utype == V_ASN1_INTEGER
            || utype == V_ASN1_ENUMERATED) {
            eosio_assert(false, "utype == V_ASN1_NULL");
        }

        /* Free any returned 'buf' content */
        free_cont = 1;
        /*
         * Should really check the internal tags are correct but some things
         * may get this wrong. The relevant specs say that constructed string
         * types should be OCTET STRINGs internally irrespective of the type.
         * So instead just check for UNIVERSAL class and ignore the tag.
         */
        if (!asn1_collect(&buf, &p, plen, inf, -1, V_ASN1_UNIVERSAL, 0)) {
            if (free_cont)
                CRYPTO_free(buf.data);
            eosio_assert(false, "!asn1_collect(&buf, &p, plen, inf, -1, V_ASN1_UNIVERSAL, 0)");
        }
        len = buf.length;
        /* Append a final null to string */
        if (!BUF_MEM_grow_clean(&buf, len + 1)) {
            if (free_cont)
                CRYPTO_free(buf.data);
            eosio_assert(false, "!BUF_MEM_grow_clean(&buf, len + 1)");
        }
        buf.data[len] = 0;
        cont = (const unsigned char *)buf.data;
    } else {
        cont = p;
        len = plen;
        p += plen;
    }

    /* We now have content length and type: translate into a structure */
    /* asn1_ex_c2i may reuse allocated buffer, and so sets free_cont to 0 */
    if (!asn1_ex_c2i(pval, cont, len, utype, &free_cont, it)){
        if (free_cont)
            CRYPTO_free(buf.data);
        eosio_assert(false, "!asn1_ex_c2i(pval, cont, len, utype, &free_cont, it)");
    }

    *in = p;
    ret = 1;
    return ret;
}

# define ASN1_OP_D2I_POST        5
# define ASN1_F_ASN1_ITEM_EMBED_D2I                       120
static bool first_flag = false;
static int asn1_item_embed_d2i(ASN1_VALUE **pval, const unsigned char **in,
                               long len, const ASN1_ITEM *it,
                               int tag, int aclass, char opt, ASN1_TLC *ctx,
                               int depth)
{
    const ASN1_TEMPLATE *tt, *errtt = NULL;
    const ASN1_EXTERN_FUNCS *ef;
    const ASN1_AUX *aux = (const ASN1_AUX_st *)it->funcs;
    ASN1_aux_cb *asn1_cb;
    const unsigned char *p = NULL, *q;
    unsigned char oclass;
    char seq_eoc, seq_nolen, cst, isopt;
    long tmplen;
    int i;
    int otag;
    int ret = 0;
    ASN1_VALUE **pchptr;
    if (pval == NULL)
        eosio_assert(false, (char *)"pval is null");
    if (aux != NULL && aux->asn1_cb != NULL)
        asn1_cb = aux->asn1_cb;
    else
        asn1_cb = 0;

    if (++depth > ASN1_MAX_CONSTRUCTED_NEST) {
        eosio_assert(false, "++depth > ASN1_MAX_CONSTRUCTED_NEST");
    }

    int tmp_type = 0;
    if(!first_flag){
        tmp_type  = 6;
        first_flag = true;
    }

    switch (tmp_type) {
        case ASN1_ITYPE_PRIMITIVE:
            return asn1_d2i_ex_primitive(pval, in, len, it,
                                         tag, aclass, opt, ctx);

        case ASN1_ITYPE_NDEF_SEQUENCE:
        case ASN1_ITYPE_SEQUENCE:
            p = *in;
            tmplen = len;

            /* If no IMPLICIT tagging set to SEQUENCE, UNIVERSAL */
            if (tag == -1) {
                tag = V_ASN1_SEQUENCE;
                aclass = V_ASN1_UNIVERSAL;
            }
            /* Get SEQUENCE length and update len, p */
            ret = asn1_check_tlen(&len, NULL, NULL, &seq_eoc, &cst,
                                  &p, len, tag, aclass, opt, ctx);

            if(!ret){
                eosio_assert(false, "!ret");
            }
            if(ret == -1){
                eosio_assert(false, "ret == -1");
            }
            if (aux && (aux->flags & ASN1_AFLG_BROKEN)) {
                len = tmplen - (p - *in);
                seq_nolen = 1;
            } else
                seq_nolen = seq_eoc;

            if(!cst){
                eosio_assert(false, "!cst");
            }
            //if (!*pval && !ASN1_item_ex_new(pval, it))
            if (ASN1_item_ex_new(pval, it) == 0)
                eosio_assert(false, (char *)"!*pval && !ASN1_item_ex_new(pval, it)");

            if (asn1_cb && !asn1_cb(ASN1_OP_D2I_PRE, pval, it, NULL))
                eosio_assert(false, (char *)"asn1_cb && !asn1_cb(ASN1_OP_D2I_PRE, pval, it, NULL)");


            /* Get each field entry */
            for (i = 0, tt = it->templates; i < it->tcount; i++, tt++) {
                const ASN1_TEMPLATE *seqtt;
                ASN1_VALUE **pseqval;
                seqtt = asn1_do_adb(pval, tt, 1);
                if(seqtt == NULL){
                    eosio_assert(false, "seqtt == NULL");
                }
                pseqval = asn1_get_field_ptr(pval, seqtt);
                /* Have we ran out of data? */
                if (len == 0)
                    break;
                q = p;
                if (asn1_check_eoc(&p, len)) {
                    if(!seq_eoc){
                        eosio_assert(false, "!seq_eoc");
                    }
                    len -= p - q;
                    seq_eoc = 0;
                    q = p;
                    break;
                }
                if (i == (it->tcount - 1))
                    isopt = 0;
                else
                    isopt = (char) (seqtt->flags & ASN1_TFLG_OPTIONAL);

                ret = asn1_template_ex_d2i(pseqval, &p, len, seqtt, isopt, ctx,
                                           depth);

                if(!ret){
                    eosio_assert(false, "!ret");
                }
                if (ret == -1) {
                    asn1_template_free(pseqval, seqtt);
                    continue;
                }
                /* Update length */
                len -= p - q;
            }

            /* Check for EOC if expecting one */
            if (seq_eoc && !asn1_check_eoc(&p, len)) {
                eosio_assert(false, "seq_eoc && !asn1_check_eoc(&p, len)");
            }
            /* Check all data read */
            if (seq_nolen != 0 && len != 0) {
                eosio_assert(false, "!seq_nolen && len");
            }

            for (; i < it->tcount; tt++, i++) {
                const ASN1_TEMPLATE *seqtt;
                seqtt = asn1_do_adb(pval, tt, 1);
                if(seqtt == NULL){
                    eosio_assert(false, "seqtt == NULL");
                }
                if (seqtt->flags & ASN1_TFLG_OPTIONAL) {
                    ASN1_VALUE **pseqval;
                    pseqval = asn1_get_field_ptr(pval, seqtt);
                    asn1_template_free(pseqval, seqtt);
                } else {
                    errtt = seqtt;
                    eosio_assert(false, "seqtt->flags & ASN1_TFLG_OPTIONAL");
                }
            }
            /* Save encoding */
            if (!asn1_enc_save(pval, *in, p - *in, it))
                eosio_assert(false, "!asn1_enc_save(pval, *in, p - *in, it)");
            if (asn1_cb && !asn1_cb(ASN1_OP_D2I_POST, pval, it, NULL))
                eosio_assert(false, "asn1_cb && !asn1_cb(ASN1_OP_D2I_POST, pval, it, NULL)");
            *in = p;
            return 1;
        default:
            eosio_assert(false, "default error");
    }

    eosio_assert(false, "return 0");
    return 0;
}

int ASN1_item_ex_d2i(ASN1_VALUE **pval, const unsigned char **in, long len,
                     const ASN1_ITEM *it,
                     int tag, int aclass, char opt, ASN1_TLC *ctx)
{
    int rv;
    rv = asn1_item_embed_d2i(pval, in, len, it, tag, aclass, opt, ctx, 0);
    if (rv <= 0)
        eosio_assert(false,"ASN1_item_ex_free(pval, it)");
    return rv;
}



ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **pval,
                          const unsigned char **in, long len,
                          const ASN1_ITEM *it)
{
    ASN1_TLC c;
    ASN1_VALUE *ptmpval = NULL;
    if (pval == NULL)
        pval = &ptmpval;
    asn1_tlc_clear_nc(&c);
    if (ASN1_item_ex_d2i(pval, in, len, it, -1, 0, 0, &c) > 0){
        if(pval == NULL)
            eosio_assert(false, "ASN1_item_d2i null");

        return *pval;
    }


    eosio_assert(false, "ASN1_item_d2i error");
    return NULL;
}

static int asn1_item_flags_i2d(ASN1_VALUE *val, unsigned char **out,
                               const ASN1_ITEM *it, int flags)
{
    if (out && !*out) {
        unsigned char *p, *buf;
        int len;

        //len = ASN1_item_ex_i2d(&val, NULL, it, -1, flags);
        if (len <= 0)
            return len;
        if ((buf = (unsigned char *)CRYPTO_malloc(len)) == NULL) {
            return -1;
        }
        p = buf;
        //ASN1_item_ex_i2d(&val, &p, it, -1, flags);
        *out = buf;
        return len;
    }

    return 0;
    //return ASN1_item_ex_i2d(&val, out, it, -1, flags);
}

int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it)
{
    return asn1_item_flags_i2d(val, out, it, 0);
}


/* Refill products of primes */
int rsa_multip_calc_product(RSA *rsa)
{
//    RSA_PRIME_INFO *pinfo;
//    BIGNUM *p1 = NULL, *p2 = NULL;
//    BN_CTX *ctx = NULL;
//    int i, rv = 0, ex_primes;
//
//    if ((ex_primes = sk_RSA_PRIME_INFO_num(rsa->prime_infos)) <= 0) {
//        /* invalid */
//        goto err;
//    }
//
//    if ((ctx = BN_CTX_new()) == NULL)
//        goto err;
//
//    /* calculate pinfo->pp = p * q for first 'extra' prime */
//    p1 = rsa->p;
//    p2 = rsa->q;
//
//    for (i = 0; i < ex_primes; i++) {
//        pinfo = sk_RSA_PRIME_INFO_value(rsa->prime_infos, i);
//        if (pinfo->pp == NULL) {
//            pinfo->pp = BN_secure_new();
//            if (pinfo->pp == NULL)
//                goto err;
//        }
//        if (!BN_mul(pinfo->pp, p1, p2, ctx))
//            goto err;
//        /* save previous one */
//        p1 = pinfo->pp;
//        p2 = pinfo->r;
//    }
//
//    rv = 1;
//    err:
//    BN_CTX_free(ctx);
//    return rv;
return 0;
}

static int rsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {
        *pval = (ASN1_VALUE *)RSA_new();
        if (*pval != NULL)
            return 2;
        return 0;
    } else if (operation == ASN1_OP_FREE_PRE) {
        RSA_free((RSA *)*pval);
        *pval = NULL;
        return 2;
    } else if (operation == ASN1_OP_D2I_POST) {
        if (((RSA *)*pval)->version != RSA_ASN1_VERSION_MULTI) {
            /* not a multi-prime key, skip */
            return 1;
        }
        return (rsa_multip_calc_product((RSA *)*pval) == 1) ? 2 : 0;
    }
    return 1;
}

#  define ASN1_ITEM_ref(iptr) (iptr##_it())
#define BN_SENSITIVE    1
# define ASN1_TFLG_SEQUENCE_OF   (0x2 << 1)

# define ASN1_SEQUENCE(tname) \
        static const ASN1_TEMPLATE tname##_seq_tt[]

# define ASN1_SEQUENCE_cb(tname, cb) \
        static const ASN1_AUX tname##_aux = {NULL, 0, 0, 0, cb, 0}; \
        ASN1_SEQUENCE(tname)

# define ASN1_EX_TYPE(flags, tag, stname, field, type) { \
        (flags), (tag), offsetof(stname, field),\
        #field, ASN1_ITEM_ref(type) }

#  define ASN1_ITEM_start(itname) \
        const ASN1_ITEM * itname##_it(void) \
        { \
                static const ASN1_ITEM local_it = {

#  define static_ASN1_ITEM_start(itname) \
        static ASN1_ITEM_start(itname)

#  define ASN1_ITEM_end(itname) \
                }; \
        return &local_it; \
        }


# define ASN1_EMBED(stname, field, type) ASN1_EX_TYPE(ASN1_TFLG_EMBED,0, stname, field, type)
# define ASN1_SIMPLE(stname, field, type) ASN1_EX_TYPE(0,0, stname, field, type)
# define ASN1_SEQUENCE_OF_OPT(stname, field, type) \
                ASN1_EX_TYPE(ASN1_TFLG_SEQUENCE_OF|ASN1_TFLG_OPTIONAL, 0, stname, field, type)

# define V_ASN1_INTEGER                  2
#define INTxx_FLAG_SIGNED       (1<<1)
#define INTxx_FLAG_ZERO_DEFAULT (1<<0)

static int uint32_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    if ((*pval = (ASN1_VALUE *)CRYPTO_zalloc(sizeof(uint32_t))) == NULL) {
        eosio_assert(false, "ASN1_F_UINT32_NEW, ERR_R_MALLOC_FAILURE");
        return 0;
    }
    return 1;
}

static void uint32_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    CRYPTO_free(*pval);
    *pval = NULL;
}

static void uint32_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    **(uint32_t **)pval = 0;
}


static size_t asn1_put_uint64(unsigned char b[sizeof(uint64_t)], uint64_t r)
{
    size_t off = sizeof(uint64_t);

    do {
        b[--off] = (unsigned char)r;
    } while (r >>= 8);

    return off;
}

static void twos_complement(unsigned char *dst, const unsigned char *src,
                            size_t len, unsigned char pad)
{
    unsigned int carry = pad & 1;

    /* Begin at the end of the encoding */
    dst += len;
    src += len;
    /* two's complement value: ~value + 1 */
    while (len-- != 0) {
        *(--dst) = (unsigned char)(carry += *(--src) ^ pad);
        carry >>= 8;
    }
}

static int uint64_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    if ((*pval = (ASN1_VALUE *)CRYPTO_zalloc(sizeof(uint64_t))) == NULL) {
        eosio_assert(false, "ASN1_F_UINT64_NEW, ERR_R_MALLOC_FAILURE");
        return 0;
    }
    return 1;
}

static size_t i2c_ibuf(const unsigned char *b, size_t blen, int neg,
                       unsigned char **pp)
{
    unsigned int pad = 0;
    size_t ret, i;
    unsigned char *p, pb = 0;

    if (b != NULL && blen) {
        ret = blen;
        i = b[0];
        if (!neg && (i > 127)) {
            pad = 1;
            pb = 0;
        } else if (neg) {
            pb = 0xFF;
            if (i > 128) {
                pad = 1;
            } else if (i == 128) {
                for (pad = 0, i = 1; i < blen; i++)
                    pad |= b[i];
                pb = pad != 0 ? 0xffU : 0;
                pad = pb & 1;
            }
        }
        ret += pad;
    } else {
        ret = 1;
        blen = 0;   /* reduce '(b == NULL || blen == 0)' to '(blen == 0)' */
    }

    if (pp == NULL || (p = *pp) == NULL)
        return ret;

    *p = pb;
    p += pad;       /* yes, p[0] can be written twice, but it's little
                     * price to pay for eliminated branches */
    twos_complement(p, b, blen, pb);

    *pp += ret;
    return ret;
}

# define ASN1_F_C2I_IBUF                                  226
# define ASN1_R_ILLEGAL_PADDING                           221
static size_t c2i_ibuf(unsigned char *b, int *pneg,
                       const unsigned char *p, size_t plen)
{
    int neg, pad;
    /* Zero content length is illegal */
    if (plen == 0) {
        eosio_assert(false, "ASN1_F_C2I_IBUF, ASN1_R_ILLEGAL_ZERO_CONTENT");
        return 0;
    }
    neg = p[0] & 0x80;
    if (pneg)
        *pneg = neg;
    /* Handle common case where length is 1 octet separately */
    if (plen == 1) {
        if (b != NULL) {
            if (neg)
                b[0] = (p[0] ^ 0xFF) + 1;
            else
                b[0] = p[0];
        }
        return 1;
    }

    pad = 0;
    if (p[0] == 0) {
        pad = 1;
    } else if (p[0] == 0xFF) {
        size_t i;

        /*
         * Special case [of "one less minimal negative" for given length]:
         * if any other bytes non zero it was padded, otherwise not.
         */
        for (pad = 0, i = 1; i < plen; i++)
            pad |= p[i];
        pad = pad != 0 ? 1 : 0;
    }
    /* reject illegal padding: first two octets MSB can't match */
    if (pad && (neg == (p[1] & 0x80))) {
        eosio_assert(false, "ASN1_F_C2I_IBUF, ASN1_R_ILLEGAL_PADDING");
        return 0;
    }

    /* skip over pad */
    p += pad;
    plen -= pad;

    if (b != NULL)
        twos_complement(b, p, plen, neg ? 0xffU : 0);

    return plen;
}

static int asn1_get_uint64(uint64_t *pr, const unsigned char *b, size_t blen)
{
    size_t i;
    uint64_t r;

    if (blen > sizeof(*pr)) {
        eosio_assert(false, "ASN1_F_ASN1_GET_UINT64, ASN1_R_TOO_LARGE");
        return 0;
    }
    if (b == NULL)
        return 0;
    for (r = 0, i = 0; i < blen; i++) {
        r <<= 8;
        r |= b[i];
    }
    *pr = r;
    return 1;
}


int c2i_uint64_int(uint64_t *ret, int *neg, const unsigned char **pp, long len)
{
    unsigned char buf[sizeof(uint64_t)];
    size_t buflen;

    buflen = c2i_ibuf(NULL, NULL, *pp, len);
    if (buflen == 0)
        return 0;
    if (buflen > sizeof(uint64_t)) {
        eosio_assert(false, "ASN1_F_C2I_UINT64_INT, ASN1_R_TOO_LARGE");
        return 0;
    }
    (void)c2i_ibuf(buf, neg, *pp, len);
    return asn1_get_uint64(ret, buf, buflen);
}

int i2c_uint64_int(unsigned char *p, uint64_t r, int neg)
{
    unsigned char buf[sizeof(uint64_t)];
    size_t off;

    off = asn1_put_uint64(buf, r);
    return i2c_ibuf(buf + off, sizeof(buf) - off, neg, &p);
}


static int uint32_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype,
                      const ASN1_ITEM *it)
{
    uint32_t utmp;
    int neg = 0;
    char *cp = (char *)*pval;
    memcpy(&utmp, cp, sizeof(utmp));

    if ((it->size & INTxx_FLAG_ZERO_DEFAULT) == INTxx_FLAG_ZERO_DEFAULT
        && utmp == 0)
        return -1;
    if ((it->size & INTxx_FLAG_SIGNED) == INTxx_FLAG_SIGNED
        && (int32_t)utmp < 0) {
        utmp = 0 - utmp;
        neg = 1;
    }

    return i2c_uint64_int(cont, (uint64_t)utmp, neg);
}


#define ABS_INT32_MIN ((uint32_t)INT32_MAX + 1)

static int uint32_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
                      int utype, char *free_cont, const ASN1_ITEM *it)
{
    uint64_t utmp = 0;
    uint32_t utmp2 = 0;
    char *cp;
    int neg = 0;

    if (*pval == NULL && !uint64_new(pval, it))
        return 0;

    cp = (char *)*pval;
    if (len == 0)
        goto long_compat;

    if (!c2i_uint64_int(&utmp, &neg, &cont, len))
        return 0;
    if ((it->size & INTxx_FLAG_SIGNED) == 0 && neg) {
        eosio_assert(false, "ASN1_F_UINT32_C2I, ASN1_R_ILLEGAL_NEGATIVE_VALUE");
        return 0;
    }
    if (neg) {
        if (utmp > ABS_INT32_MIN) {
            eosio_assert(false, "ASN1_F_UINT32_C2I, ASN1_R_TOO_SMALL");
            return 0;
        }
        utmp = 0 - utmp;
    } else {
        if (((it->size & INTxx_FLAG_SIGNED) != 0 && utmp > INT32_MAX)
            || ((it->size & INTxx_FLAG_SIGNED) == 0 && utmp > UINT32_MAX)) {
            eosio_assert(false, "ASN1_F_UINT32_C2I, ASN1_R_TOO_LARGE");
            return 0;
        }
    }

    long_compat:
    utmp2 = (uint32_t)utmp;
    memcpy(cp, &utmp2, sizeof(utmp2));
    return 1;
}


static ASN1_PRIMITIVE_FUNCS uint32_pf = {
        NULL, 0,
        uint32_new,
        uint32_free,
        uint32_clear,
        uint32_c2i,
        uint32_i2c
};





int BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
    return bn2binpad(a, to, -1);
}


static int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    *pval = (ASN1_VALUE *)BN_new();
    if (*pval != NULL)
        return 1;
    else
        return 0;
}

static int bn_secure_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    *pval = (ASN1_VALUE *)BN_secure_new();
    if (*pval != NULL)
        return 1;
    else
        return 0;
}

static void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    if (!*pval)
        return;
    if (it->size & BN_SENSITIVE)
        BN_clear_free((BIGNUM *)*pval);
    else
        BN_free((BIGNUM *)*pval);
    *pval = NULL;
}

static int bn_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype,
                  const ASN1_ITEM *it)
{
    BIGNUM *bn;
    int pad;
    if (!*pval)
        return -1;
    bn = (BIGNUM *)*pval;
    /* If MSB set in an octet we need a padding byte */
    if (BN_num_bits(bn) & 0x7)
        pad = 0;
    else
        pad = 1;
    if (cont) {
        if (pad)
            *cont++ = 0;
        BN_bn2bin(bn, cont);
    }
    return pad + BN_num_bytes(bn);
}

static int bn_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
                  int utype, char *free_cont, const ASN1_ITEM *it)
{
    BIGNUM *bn;

    if (*pval == NULL && !bn_new(pval, it))
        return 0;
    bn = (BIGNUM *)*pval;
    if (!BN_bin2bn(cont, len, bn)) {
        bn_free(pval, it);
        return 0;
    }
    return 1;
}

static int bn_secure_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
                         int utype, char *free_cont, const ASN1_ITEM *it)
{
    if (!*pval)
        bn_secure_new(pval, it);
    return bn_c2i(pval, cont, len, utype, free_cont, it);
}

static ASN1_PRIMITIVE_FUNCS bignum_pf = {
        NULL, 0,
        bn_new,
        bn_free,
        0,
        bn_c2i,
        bn_i2c
};



ASN1_ITEM_start(INT32)
                    ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &uint32_pf,
                    INTxx_FLAG_SIGNED, "INT32"
ASN1_ITEM_end(INT32)

ASN1_ITEM_start(BIGNUM)
                    ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &bignum_pf, 0, "BIGNUM"
ASN1_ITEM_end(BIGNUM)


static ASN1_PRIMITIVE_FUNCS cbignum_pf = {
        NULL, 0,
        bn_secure_new,
        bn_free,
        0,
        bn_secure_c2i,
        bn_i2c
};

ASN1_ITEM_start(CBIGNUM)
                    ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &cbignum_pf, BN_SENSITIVE, "CBIGNUM"
ASN1_ITEM_end(CBIGNUM)


# define ASN1_SEQUENCE_END_ref(stname, tname) \
        ;\
        ASN1_ITEM_start(tname) \
                ASN1_ITYPE_SEQUENCE,\
                V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(ASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #tname \
        ASN1_ITEM_end(tname)

# define ASN1_SEQUENCE_END_cb(stname, tname) ASN1_SEQUENCE_END_ref(stname, tname)

ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = {
        ASN1_EMBED(RSA, version, INT32),
        ASN1_SIMPLE(RSA, n, BIGNUM),
        ASN1_SIMPLE(RSA, e, BIGNUM),
        ASN1_SIMPLE(RSA, d, CBIGNUM),
        ASN1_SIMPLE(RSA, p, CBIGNUM),
        ASN1_SIMPLE(RSA, q, CBIGNUM),
        ASN1_SIMPLE(RSA, dmp1, CBIGNUM),
        ASN1_SIMPLE(RSA, dmq1, CBIGNUM),
        ASN1_SIMPLE(RSA, iqmp, CBIGNUM)
        //ASN1_SEQUENCE_OF_OPT(RSA, prime_infos, RSA_PRIME_INFO)
} ASN1_SEQUENCE_END_cb(RSA, RSAPrivateKey)

#  define ASN1_ITEM_rptr(ref) (ref##_it())



# define IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(stname, itname, fname) \
        stname *d2i_##fname(stname **a, const unsigned char **in, long len) \
        { \
               return (stname *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, (const ASN1_ITEM *)ASN1_ITEM_rptr(itname));\
        }

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(RSA, RSAPrivateKey, RSAPrivateKey)


int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key)
{
    pkey->pkey.ptr = key;
    return (key != NULL);
}



static int old_rsa_priv_decode(EVP_PKEY *pkey,
                               const unsigned char **pder, int derlen)
{
    RSA *rsa = NULL;
    rsa = d2i_RSAPrivateKey(NULL, pder, derlen);
    if ( rsa == NULL) {
        eosio_assert(false, (char *)"RSA_F_OLD_RSA_PRIV_DECODE, ERR_R_RSA_LIB");
    }


    EVP_PKEY_assign(pkey, 6, rsa);
    return 1;
}


EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp,
                         long length)
{
    EVP_PKEY *ret;
    const unsigned char *p = *pp;

    if ((a == NULL) || (*a == NULL)) {
        if ((ret = EVP_PKEY_new()) == NULL) {
            eosio_assert(false,"ASN1_F_D2I_PRIVATEKEY, ERR_R_EVP_LIB");
            return NULL;
        }
    } else {
        ret = *a;
    }

    if(!old_rsa_priv_decode(ret, &p, length)) {
        if (a == NULL || *a != ret)
            CRYPTO_free(ret);
        eosio_assert(false, "old_rsa_priv_decode");
    }

    *pp = p;
    if (a != NULL)
        (*a) = ret;
    return ret;
}

# define PEM_STRING_EVP_PKEY     "ANY PRIVATE KEY"
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp)
{
    char *nm = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    int slen;
    EVP_PKEY *ret = NULL;

    if (!PEM_bytes_read_bio_secmem(&data, &len, &nm, PEM_STRING_EVP_PKEY, bp))
        return NULL;
    p = data;

    if ((slen = pem_check_suffix(nm, "PRIVATE KEY")) > 0) {
        ret = d2i_PrivateKey(6, NULL, &p, len);
    }

    p8err:
    err:
    CRYPTO_clear_free(nm,strlen(nm));
    CRYPTO_clear_free(data, len);
    return ret;
}


RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
    return pkey->pkey.rsa;
}

RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey)
{
    RSA *ret = EVP_PKEY_get0_RSA(pkey);
    return ret;
}

static RSA *pkey_get_rsa(EVP_PKEY *key, RSA **rsa)
{
    RSA *rtmp;
    if (!key)
        return NULL;
    rtmp = EVP_PKEY_get1_RSA(key);
    if (!rtmp)
        return NULL;
    if (rsa) {
        RSA_free(*rsa);
        *rsa = rtmp;
    }
    return rtmp;
}


RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa)
{
    EVP_PKEY *pktmp;
    pktmp = PEM_read_bio_PrivateKey(bp);
    return pkey_get_rsa(pktmp, rsa);
}


int RSA_private_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding)
{
    //return rsa->meth->rsa_priv_dec(flen, from, to, rsa, padding);
    return rsa_ossl_private_decrypt(flen, from, to, rsa, padding);
}



void BIO_free_all(BIO *bio)
{
    BIO *b;
    int ref;

    while (bio != NULL) {
        b = bio;
        ref = b->references;
        bio = bio->next_bio;
        BIO_free(b);
        /* Since ref count > 1, don't free anyone else. */
        if (ref > 1)
            break;
    }
}



