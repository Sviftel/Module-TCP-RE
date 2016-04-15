#ifndef CACHE_STRUCTURE_H
#define CACHE_STRUCTURE_H


#include <linux/hashtable.h>
#include <linux/rbtree.h>

// don't forget to change __get_key_from_hash
// function if you are changing size of hash_table
#define CACHE_BITS_NUM 16


struct cache {
    struct rb_root tree;
    DECLARE_HASHTABLE(ht, CACHE_BITS_NUM);
    long max_size;      // in bytes
    long curr_size;     // in bytes
    int hits;
    int misses;
};

// cache_size in MB
void init_cache(struct cache *c, int cache_size);
void clean_cache(struct cache *c);

void add_to_cache(struct cache *c, unsigned char *pl, int s);

// TODO: test the function
// void get_pl_info(struct cache *c, unsigned char *hash_val,
//                  unsigned char *pl, int *pl_s);

int get_hitrate(struct cache *c);


/******/
void __get_hash_key_to_buff(unsigned char *pl, int s,
                        unsigned char *hash, unsigned int *key);
/******/


#endif
