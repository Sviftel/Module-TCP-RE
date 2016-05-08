#include "hashing.h"
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>


struct crypto_hash *tfm;
struct hash_desc desc;


void alloc_hash_structs(void) {
    tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);

    desc.tfm = tfm;
    desc.flags = 0;
}


void calc_hash(const unsigned char *buf,
               unsigned int buf_len,
               unsigned char *output)
{
    crypto_hash_init(&desc);
    struct scatterlist sg;
    sg_init_one(&sg, buf, buf_len);
    crypto_hash_update(&desc, &sg, buf_len);
    crypto_hash_final(&desc, output);
}


void free_hash_structs(void) {
    crypto_free_hash(tfm);
}