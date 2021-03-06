#ifndef CACHE_STRUCTURE_H
#define CACHE_STRUCTURE_H


#include "hpl_entry.h"
#include <linux/hashtable.h>
#include <linux/rbtree.h>


// don't forget to change __get_key_from_hash
// function if you are changing size of hash_table
#define CACHE_BITS_NUM 16

#define ID_LEN 1
#define TOTAL_HASH_INFO_LEN (HASH_LEN + ID_LEN)


struct cache {
    struct rb_root tree;
    DECLARE_HASHTABLE(ht, CACHE_BITS_NUM);
    long max_size;      // in bytes
    long curr_size;     // in bytes
    int hits;
    int misses;
    long long saved_traffic_size;
    long long total_traffic_size;
};

// cache_size in MB
void init_cache(struct cache *c, int cache_size);
void clean_cache(struct cache *c);

// function returns non-nil hash value and ID 
// if payload is already stored in the cache
void add_to_cache(struct cache *c,
                  const unsigned char *pl,
                  int s,
                  unsigned char **hash_val,
                  unsigned char *id);

// function updates keys of the payload
void get_pl_info(struct cache *c,
                 const unsigned char *hash_val,
                 unsigned char id,
                 unsigned char **pl,
                 int *pl_s);

void __cache_del_entry(struct cache *c);

int get_hitrate(struct cache *c);
int get_saved_traffic_part(struct cache *c);

#endif
